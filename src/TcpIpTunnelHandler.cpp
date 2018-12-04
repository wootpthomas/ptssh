/**************************************************************************
*   Copyright (C) 2008-2009 by Paul Thomas thomaspu@gmail.com
*   All rights reserved.
*
*   This file is part of PTssh
*
*   Permission to use, copy, modify, and distribute this software for any purpose
*   with or without fee is hereby granted, provided that the above copyright
*   notice and this permission notice appear in all copies.
*
*   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
*   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
*   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS. IN
*   NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
*   DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
*   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
*   OR OTHER DEALINGS IN THE SOFTWARE.
*
*   Except as contained in this notice, the name of a copyright holder shall not
*   be used in advertising or otherwise to promote the sale, use or other dealings
*   in this Software without prior written authorization of the copyright holder.
*************************************************************************/



/*************************
 * Includes
 ************************/
#include "TcpIpTunnelHandler.h"


#ifdef WIN32
#   include <winsock2.h>

	//Redefine the close() function on windows so we don't break on linux
#   define close(SOCKET)				closesocket(SOCKET)
#else
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <errno.h>
#endif


#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif

#include <stdio.h>
#include <string.h>



#include "Utility.h"
#include "ChannelManager.h"
#include "LinkedList.h"
#include "BinaryPacket.h"
#include "SSH2Types.h"
#include "PTssh.h"
#include "PTsshLog.h"

///////////////////////////////////////////////////////////////////////////////
TcpIpTunnelHandler::TcpIpTunnelHandler(PTssh * const pSSH, ChannelManager * const pChannelMgr):
TunnelHandler(pSSH, pChannelMgr)
{

}

///////////////////////////////////////////////////////////////////////////////
TcpIpTunnelHandler::~TcpIpTunnelHandler(void)
{

}

///////////////////////////////////////////////////////////////////////////////
int32
TcpIpTunnelHandler::init(
	int localPort,
	int totalConnections,
	int32 (*callbackFuncPtr)(void *ptrStorage),
	const char *destAddress,
	uint16 destPort,
	const char *sourceIPAddress,
	uint16 sourcePort)
{
	pthread_t
		listenThreadObj;
	pthread_attr_t
		threadAttr;
	int32 
		result = PTSSH_SUCCESS;

	m_localPort = localPort;
	m_totalConnections = totalConnections;
	m_pDestAddress = strdup(destAddress);
	m_pSourceIPAddress = strdup(sourceIPAddress);
	m_sourcePort = sourcePort;
	m_destPort = destPort;
	m_pCallbackFuncPtr = callbackFuncPtr;

	sockaddr_in sockAddr;

	//Try and create and bind a socket to localSocket so we can listen on it
	result = createSocket(m_boundLocalSocket, &sockAddr, m_pSourceIPAddress, m_localPort, true, totalConnections);
	if ( result != PTSSH_SUCCESS)
	{
		PTLOG((LL_error, "[TH] Error: Could not create or bind local socket for listening\n"));
		return result;
	}

	m_pHandlers = new LinkedList();
	if (m_pHandlers)
	{
		/* Let's spin off a thread to listen for incoming connections */
		struct threadReturnData
			*pTRDListenSocket = NULL,
			*pTRDListenChannel = NULL;

		pthread_mutex_init( &m_mutex, NULL);

		pthread_attr_init( &threadAttr);
		pthread_attr_setdetachstate(&threadAttr, PTHREAD_CREATE_JOINABLE);

		//Create thread to listen for incoming connections on our local port
		result = pthread_create( &listenThreadObj, &threadAttr, listenForConnectionsThread, (void*)this);
		if ( result == 0)
		{
			result = PTSSH_SUCCESS;
			PTLOG((LL_debug1, "****************\nTunnel handler listening for incoming connections!\n****************\n"));
		}
		else
		{
			result = PTSSH_FAILURE;
			PTLOG((LL_error, "****************\nTunnel unable to start!\n****************\n"));
		}

		//cleanup
		pthread_attr_destroy( &threadAttr);
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
void
TcpIpTunnelHandler::shutdown()
{
	struct threadData *pTD = NULL;

	//Shutdown our thread that listens and accepts connections
	pthread_mutex_lock( &m_mutex);
		m_bShutdown = true;
	pthread_mutex_unlock( &m_mutex);

	//Wait for the listening thread to exit
	pthread_join( m_listenThreadObj, NULL);

	//For each thread-data pair in our list, tell each one to shutdown and wait till threads exit
	pthread_mutex_lock( &m_mutex);
		while ( pTD = (struct threadData*)m_pHandlers->removeFirst() )
		{
			pthread_mutex_lock( &pTD->generalMutex);
				pTD->bShutdown = true;
			pthread_mutex_unlock( &pTD->generalMutex);

			//Wait for threads to check shutdown status and exit
			pthread_join( pTD->threadSocketToChannelObj, NULL);
			pthread_join( pTD->threadChannelToSocketObj, NULL);

			//Gracefully close the channel
			m_pSSH->closeChannel( pTD->cNum);

			pthread_mutex_destroy( &pTD->generalMutex);

			//delete the thread data object
			delete pTD;
			pTD = NULL;
		}
	pthread_mutex_unlock( &m_mutex);
}

///////////////////////////////////////////////////////////////////////////////
void *
TcpIpTunnelHandler::listenForConnectionsThread(void *pTunnelHandler)
{
	//Alright, let's get out of the static realm and get back in our class
	((TcpIpTunnelHandler*)pTunnelHandler)->listenForConnectionsEntry();

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
void *
TcpIpTunnelHandler::listenForConnectionsEntry()
{
	int32 result;

	//Listen for a connection to the socket
	timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 5000;

	/* Create and clear out our fd_set */
	fd_set readfds;
	while ( 1)
	{
		bool bShutdown;
		FD_ZERO( &readfds);

		//Add this file descriptor to our list of FDs to check
		FD_SET( m_boundLocalSocket, &readfds);

		//Check to see if we should shutdown 
		pthread_mutex_lock( &m_mutex);
			bShutdown = m_bShutdown;
		pthread_mutex_unlock( &m_mutex);

		if ( bShutdown)
			break;
		
		//Wait for a process to connect to our local socket
		result = select(m_boundLocalSocket + 1, &readfds, NULL, NULL, &timeout);
		if (result < 0)
		{
			PTLOG((LL_error, "[TH] ListenForConnections: encountered an error: %d\n", result));
			break;
		}
		else if ( result > 0)
		{
			if (FD_ISSET( m_boundLocalSocket, &readfds) )
			{
				//Accept the connection and setup a tunnel
				PTLOG((LL_info, "[TH] Client connected, setting up tunnel!\n"));
				handleNewConnection();
			}
		}
	}

	//TODO: Wait for all tunnelHandler threads to stop before closing socket
	//Of course killing the socket will also end up killing the threads...
	
	PTLOG((LL_debug1, "[TH] ListenForConnections: exiting!\n"));
	pthread_exit( NULL);
	return NULL;
}

////////////////////////////////////////////////////////////////////////////////////
bool
TcpIpTunnelHandler::handleNewConnection()
{
	int32
		result;
	uint32
		cNum = PTSSH_BAD_CHANNEL_NUMBER;
	struct sockaddr_in 
		*pClientAddress = new sockaddr_in;
	int
		rc,
		len = sizeof(*pClientAddress),
#ifdef WIN32
		tunnelSock = accept( m_boundLocalSocket, (sockaddr*) pClientAddress, &len);
#else
		tunnelSock = accept( m_boundLocalSocket, (sockaddr*) pClientAddress, (socklen_t*)&len);
#endif
	if ( tunnelSock < 0)
	{
		PTLOG((LL_debug1, "[TH] Accepting an incoming socket errored with code %d\n", tunnelSock));
		return false;
	}

	if ( ! setSocketBlocking(tunnelSock, false) ){
		PTLOG((LL_warning, "Warning! Could not set socket to non-blocking!\n"));
	}

	//We have negotiated a socket. Let's create a channel to use for the tunnel
	result = m_pSSH->createChannel_directTCPIP(
		cNum,
		m_pDestAddress,
		m_destPort,
		m_pSourceIPAddress,
		m_sourcePort);
	if ( result == PTSSH_SUCCESS)
	{
		//We will let the two threads we spawn here share the parent's threadData object.
		//Ok, the socket has been negotiated and the channel created. Start forwarding traffic!
		struct threadReturnData
			*pTRDListenSocket = NULL,
			*pTRDListenChannel = NULL;
		pthread_attr_t 
			threadAttr;
		
		pthread_attr_init( &threadAttr);
		pthread_attr_setdetachstate(&threadAttr, PTHREAD_CREATE_JOINABLE);

		struct threadData *pTD = new threadData();
		if ( pTD)
		{
			pTD->pSSH = m_pSSH;
			pTD->cNum = cNum;
			pTD->tunnelSock = tunnelSock;
			pTD->callbackFuncPtr = m_pCallbackFuncPtr;
			pthread_mutex_init( &pTD->generalMutex, NULL);

			//Create threads to handling forwarding the data
			rc = pthread_create( &pTD->threadSocketToChannelObj, &threadAttr, socketToChannelThread, (void*)pTD);
			rc = pthread_create( &pTD->threadChannelToSocketObj, &threadAttr, channelToSocketThread, (void*)pTD);

			//Status
			PTLOG((LL_debug1, "****************\nTunnel is alive!\n****************\n"));

			//register the thread-pair
			pthread_mutex_lock( &m_mutex);
				m_pHandlers->insertAtEnd((void*)pTD);
			pthread_mutex_unlock( &m_mutex);

			////Wait for the tunnel to be closed or a socket error: causes threads to exit
			//pthread_join( threadSocketToChannelObj, &pThreadSocketStatus);
			//pthread_join( threadChannelToSocketObj, &pThreadChannelStatus);

			//Status
			//PTLOG((LL_debug1, "****************\nTunnel shutting down\n****************\n"));
		}

		//cleanup
		pthread_attr_destroy( &threadAttr);

		////Inspect thread exit data... and delete when finished
		//delete pThreadSocketStatus;
		//delete pThreadChannelStatus;

		//Close the channel we used
		//result = pTD->pSSH->closeChannel(pTD->cNum);
		//Delete the channel

		//pthread_mutex_destroy( &m_mutex);
		//delete pTD;
	}

	return true;
}
