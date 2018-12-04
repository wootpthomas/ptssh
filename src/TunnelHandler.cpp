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
#include "TunnelHandler.h"

#include <string.h>
#include <stdio.h>
#include <time.h>

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

#include "PTssh.h"
#include "Utility.h"
#include "Data.h"
#include "LinkedList.h"
#include "ChannelManager.h"
#include "PTsshLog.h"

///////////////////////////////////////////////////////////////////////////////
TunnelHandler::TunnelHandler(PTssh * const pSSH, ChannelManager * const pChannelMgr):
m_pSSH(pSSH),
m_pChannelMgr(pChannelMgr),
m_pCallbackFuncPtr(NULL),
m_bShutdown(false),
m_bIsShutdown(false),
m_localSocket( PTSSH_BAD_SOCKET_NUMBER),
m_pSourceIPAddress(0),
m_totalConnections(1)
{

}

///////////////////////////////////////////////////////////////////////////////
TunnelHandler::~TunnelHandler(void)
{

}

///////////////////////////////////////////////////////////////////////////////
/**
* The purpose of this thread is just to sit and listen for data on the socket. When we
* receive data, we immediately write it to the channel. Meanwhile, our main thread is
* handling the other part: When it receives data on the channel, it immediately writes
* it to the socket.
*/
void* 
TunnelHandler::socketToChannelThread( void *pThreadData)
{
	struct threadData *pTD = (struct threadData*)pThreadData;

	//As long as the socket is alive, keep reading date off of it and write it to the channel
	bool
		bConnected = true,
		bShutdownFlag = false;
	int
		result,
		error,
		bytesRead = 0;
	fd_set 
		readfds;
	char 
		buf[1024];

	//Listen for a connection to the socket
	timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 5000;

	while (bConnected)
	{
		//Check to make sure we should keep going
		pthread_mutex_lock( &pTD->generalMutex);
			bShutdownFlag = pTD->bShutdown;
		pthread_mutex_unlock( &pTD->generalMutex);

		if ( bShutdownFlag)
			break;

		FD_ZERO( &readfds);

		//Add this file descriptor to our list of FDs to check
		FD_SET( pTD->tunnelSock, &readfds);
		
		//Wait for a process to connect to our local socket
		result = select(pTD->tunnelSock + 1, &readfds, NULL, NULL, &timeout);
		if (result < 0)
		{
			PTLOG((LL_error, "[TH S->C%d ] encountered an error: %d\n", pTD->cNum, result));
			bConnected = false;
		}
		else if ( result > 0)
		{
			/* yay! Theres data available to be read from the socket
			 * Read the data off and pass it on to PTssh */
			do {
				bytesRead = recv( pTD->tunnelSock, buf, 1024, 0);

				//Check for error. If WSAEWOULDBLOCK, then theres no further data available from the socket
				if ( bytesRead <= 0 )
				{
					if ( bytesRead == 0){
						PTLOG((LL_info, "[TH S->C %d] Client disconnected from socket.\n", pTD->cNum));
					}
#ifdef WIN32
					error = WSAGetLastError();
					if (error == WSAEWOULDBLOCK)
						continue;
					else if ( error != WSAEWOULDBLOCK)
#else
					error = errno;
					if (error == EAGAIN)
						continue;
					else if ( error != EAGAIN)
#endif
					{
						if ( bytesRead != 0){
							PTLOG((LL_error, "[TH S->C %d] Encountered an error during recv() and is shutting down! Error %d\n", pTD->cNum, error));
						}

						bConnected = false;

						/* Set the shared variable so that the next time our listenChannelThread
						 * checks the socket status, it'll know its dead */
						pthread_mutex_lock( &pTD->generalMutex);
							pTD->bIsSocketAlive = false;
						pthread_mutex_unlock( &pTD->generalMutex);
					}
				}
				else
				{
					result = pTD->pSSH->channelWrite( pTD->cNum, (const char *)&buf, bytesRead);
					if ( result != PTSSH_SUCCESS)
					{
						PTLOG((LL_error, "[TH S->C %d] Error while writing to PTssh: %d\n", pTD->cNum, result));
						bConnected = false;
					}
					//else
					//	PTLOG(("[TH S->C %d] Socket -> channel %d bytes\n", pTD->cNum, bytesRead));
				}

			} while (bytesRead > 0);
		}
		else
			continue;
	}


	//This thread does the cleanup for the socket and channel
	//Alert the other thread to shutdown
	pthread_mutex_lock( &pTD->generalMutex);
		pTD->bIsSocketAlive = false;
		pTD->bShutdown = true;
	pthread_mutex_unlock( &pTD->generalMutex);

	//Wait for the other thread to stop so we can safely close the channel and socket
	pthread_join( pTD->threadChannelToSocketObj, NULL);

	//Close the socket
	close(pTD->tunnelSock);

	//Close the channel
	pTD->pSSH->closeChannel( pTD->cNum);

	PTLOG((LL_info, "[TH S->C %d] Thread exiting!\n", pTD->cNum));
	pthread_exit( NULL);
	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
void *
TunnelHandler::channelToSocketThread(void *pThreadData)
{
	struct 
		threadData *pTD = (struct threadData*)pThreadData;
	int 
		error = 0,
		result;
	Data 
		*pData = NULL;
	bool 
		bKeepGoing = true;

	//Go into writing loop
	while (bKeepGoing)
	{
		//Listen for 1msec
		result = pTD->pSSH->channelRead(pTD->cNum, &pData, true, 1000);
		if ( result == PTSSH_SUCCESS)
		{
			int 
				bytesSent = 0;
			uint32
				dataLen = pData->dataLen(),
				totalSent = 0;
			//PTLOG(("[TH C->S %d] Channel -> socket %d bytes\n", pTD->cNum, dataLen));

			do {
				//Write the data to the socket
				bytesSent = send(
					pTD->tunnelSock, 
					(const char*)pData->getDataPtr() + totalSent, 
					dataLen - totalSent,
					0);

				if (bytesSent <= 0)
				{
#ifdef WIN32
					error = WSAGetLastError();
					if ( error == WSAEWOULDBLOCK)
#else
					error = errno;
					if ( error == EAGAIN)
#endif
					{
						bytesSent = 0;
						continue;
					}
					else
					{
						PTLOG((LL_error, "[TH C->S %d] Socket sending error %d!\n", pTD->cNum, error));
						bKeepGoing = false;
						break;
					}
				}
				else
					totalSent += bytesSent;

			} while (bKeepGoing && totalSent < dataLen);

			if ( bytesSent != dataLen)
				bKeepGoing = false;

			//Cleanup so we don;t leak
			delete pData;
			pData = NULL;
		}
		else if (result == PTSSH_ERR_NoDataAvailable)
		{
			/* Now heres the thing, since we are listening on the SSH channel, we won't
			 * immediately know when the tunnel has died as a result of the socket closing
			 * or a socket error occuring. So we depend on the thread that's listening
			 * on the socket to let us know through a shared variable if the socket is
			 * still alive */
			pthread_mutex_lock( &pTD->generalMutex);
				if ( ! pTD->bIsSocketAlive || pTD->bShutdown)
				{
					//Socket is dead -or- we've recieved the shutdown flag, exit next time through our loop
					bKeepGoing = false;
				}
			pthread_mutex_unlock( &pTD->generalMutex);
		}
		else
		{
			bKeepGoing = false;
			PTLOG((LL_error, "[TH C->S %d] Channel read failure, exiting. Error %d\n", pTD->cNum, result));
		}
	}

	PTLOG((LL_info, "[TH C->S %d] Thread exiting!\n", pTD->cNum));
	pthread_exit( NULL);
	return NULL;
}



