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


#include "X11TunnelHandler.h"
#include "Utility.h"
#include "ChannelManager.h"
#include "LinkedList.h"
#include "BinaryPacket.h"
#include "SSH2Types.h"
#include "PTssh.h"
#include "PTsshLog.h"

///////////////////////////////////////////////////////////////////////////////
X11TunnelHandler::X11TunnelHandler(PTssh * const pSSH, ChannelManager * const pChannelMgr):
TunnelHandler(pSSH, pChannelMgr),
m_pTD(0),
pXServerIPAddress(0)
{

}

///////////////////////////////////////////////////////////////////////////////
X11TunnelHandler::~X11TunnelHandler(void)
{

}

///////////////////////////////////////////////////////////////////////////////
void
X11TunnelHandler::shutdown()
{
	if ( m_pTD)
	{
		pthread_mutex_lock( &m_pTD->generalMutex);
			m_pTD->bShutdown = true;
		pthread_mutex_unlock( &m_pTD->generalMutex);

		//Wait for threads to check shutdown status and exit
		pthread_join( m_pTD->threadSocketToChannelObj, NULL);
		//pthread_join( m_pTD->threadChannelToSocketObj, NULL);

		//Delete the channel
		int32 result = m_pChannelMgr->deleteChannel( m_pTD->cNum );
		if ( result != PTSSH_SUCCESS){
			PTLOG((LL_error, "[X11TH] Error deleting channel\n"));
		}


		pthread_mutex_destroy( &m_pTD->generalMutex);

		//delete the thread data object
		delete m_pTD;
		m_pTD = NULL;
	}
}

///////////////////////////////////////////////////////////////////////////////
int32
X11TunnelHandler::init(uint32 localChannel, const char *XServerIPAddress, uint16 XServerPort)
{
	int32 result = PTSSH_SUCCESS;

	bool
		bCloseChannel = true,
		bSendFailure = true;
	BinaryPacket 
		*pBP = NULL;
	uint32
		len = 0,
		remoteChannel;

	//Create a new socket
	sockaddr_in sockAddr;

	//Try and create and bind a socket to localSocket so we can listen on it
	result = createSocket(m_x11Sock, &sockAddr, XServerIPAddress, XServerPort, false);
	if ( result != PTSSH_SUCCESS)
	{
		PTLOG((LL_error, "[X11TH] Error: Could not connect to X11 server!\n"));
		goto errorCleanup;
	}

	if ( ::connect(m_x11Sock, (struct sockaddr*)&sockAddr, sizeof(struct sockaddr_in)) != 0) 
	{
		close(m_x11Sock);
		goto errorCleanup;
	}

	//Set the socket to non-blocking
	if ( ! setSocketBlocking(m_x11Sock, true) )
	{
		PTLOG((LL_error, "[X11TH] Error: Could not set socket to non-blocking\n"));
		close(m_x11Sock);
		goto errorCleanup;
	}


	//Cool, we have an X11 server. Let's accept the channel open request
	remoteChannel = PTSSH_BAD_CHANNEL_NUMBER,
	len =
		1 + //	    byte      SSH_MSG_CHANNEL_OPEN_CONFIRMATION
		4 + //      uint32    recipient channel
		4 + //      uint32    sender channel
		4 + //      uint32    initial window size
		4;  //      uint32    maximum packet size
	
	result = m_pChannelMgr->getRemoteChannelNumber(localChannel, remoteChannel);
	if ( result != PTSSH_SUCCESS)
		goto errorCleanup;
	
	pBP = new BinaryPacket();
	if ( pBP && pBP->init(len))
	{
		pBP->writeByte( SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
		pBP->writeUint32( remoteChannel);
		pBP->writeUint32( localChannel);
		pBP->writeUint32( PTSSH_DEFAULT_WINDOW_SIZE);
		pBP->writeUint32( PTSSH_MAX_PACKET_SIZE);

		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result == PTSSH_SUCCESS)
		{
			struct threadReturnData
				*pTRDListenSocket = NULL,
				*pTRDListenChannel = NULL;
			pthread_attr_t 
				threadAttr;
			
			pthread_attr_init( &threadAttr);
			pthread_attr_setdetachstate(&threadAttr, PTHREAD_CREATE_JOINABLE);

			int rc; //Thread return code

			/* We assume that the open confirmation got to its destination. Lets kick off
			 * the two threads so that they can star servicing the x11 tunnel */
			m_pTD = new threadData();
			if ( m_pTD)
			{
				m_pTD->cNum = localChannel;
				m_pTD->tunnelSock = m_x11Sock;
				m_pTD->callbackFuncPtr = NULL;
				m_pTD->pSSH = m_pSSH;
				pthread_mutex_init( &m_pTD->generalMutex, NULL);
				pthread_mutex_init( &m_mutex, NULL);

				//Create threads to handling forwarding the data
				rc = pthread_create( &m_pTD->threadSocketToChannelObj, &threadAttr, socketToChannelThread, (void*)m_pTD);
				rc = pthread_create( &m_pTD->threadChannelToSocketObj, &threadAttr, channelToSocketThread, (void*)m_pTD);

				//Status
				PTLOG((LL_info, "****************\nX11 Tunnel is alive on channel %01d, socket %d!\n****************\n", 
					localChannel, m_x11Sock));

				//cleanup
				//pthread_attr_destroy( &threadAttr);

				bCloseChannel = false;
				bSendFailure = false;
			}
		}
		else
		{
			delete pBP;
			pBP = NULL;
		}
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;


errorCleanup:

	if ( bCloseChannel)
	{
		m_pChannelMgr->deleteChannel(localChannel, false);
	}

	if ( bSendFailure)
	{
//TODO: send packet rejecting the channel open

	}

	return result;
}