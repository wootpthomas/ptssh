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

#ifndef _TUNNELHANDLER
#define _TUNNELHANDLER

/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"
#include <pthread.h>


/*************************
* Forward declarations
*************************/
class PTssh;
class ChannelManager;
class LinkedList;


/**
* This class was designed be a base class that provides some of the basic 
* functionallity for local and X11 tunneling. */
class TunnelHandler
{
public:

	struct threadData{
		PTssh
			*pSSH;
		uint32 
			cNum;

		int 
			tunnelSock;

		int32 
			(*callbackFuncPtr)(void *ptrStorage);

		pthread_t
			threadSocketToChannelObj,
			threadChannelToSocketObj;

		pthread_mutex_t
			generalMutex;	//We use this mutex to safeguard read/write access to bShutdown
		bool
			bShutdown,		//Threads check this often so they know when to shutdown
			bIsSocketAlive; //Lets either thread tell the other one the socket is dead

		threadData()
		{
			pSSH = NULL;
			cNum = PTSSH_BAD_CHANNEL_NUMBER;
			tunnelSock = PTSSH_BAD_SOCKET_NUMBER;
			bShutdown = false;
			bIsSocketAlive = true;
			callbackFuncPtr = NULL;
		}
	};

	TunnelHandler(PTssh * const pSSH, ChannelManager * const pChannelMgr);
	~TunnelHandler(void);


	/**
	* The calling process that created this object can tell it to shutdown. When we
	* get called, we must immediately stop, close channels and cleanup because we
	* are about to be terminated. Any errors should be silently ignored.
	*/
	virtual void shutdown() = 0;
	
	
	
	/*********************
	* Thread Entry points -> These call the respective class members
	*********************/

	/**
	 * This listens for data on the socket. When it gets data, it writes
	 * it to the given SSH channel number. When the socket closes or an error
	 * occurs, this thread will exit.
	 */
	static void * socketToChannelThread(void *pThreadData);

	/**
	 * This listens for data on the channel. When it gets data, it writes
	 * it to the given socket number. When the socket closes or an error
	 * occurs, this thread will exit. 
	 */
	static void * channelToSocketThread(void *pThreadData);

	/**
	* Returns the local port number that this tunnel handler is listening or
	* running on.
	*/
	int getListenSocketNumber() { return (int)m_localPort; }

protected:


	PTssh 
		* const m_pSSH;  /**< Pointer to our PTssh instance so that we can interact
						 with it and create channels and forward data and such */
	ChannelManager
		* const m_pChannelMgr; /**< Pointer to our channel manager so that we can 
						send things like channel open confirmations */
			
	char
		*m_pSourceIPAddress;

	int
		m_localSocket,
		m_totalConnections;

	int32 
		(*m_pCallbackFuncPtr)(void *ptrStorage);

	uint16
		m_localPort;

	pthread_t
		m_listenThreadObj;
	pthread_mutex_t
		m_mutex;

	bool 
		m_bShutdown,
		m_bIsShutdown;

	LinkedList
		*m_pHandlers;    /**< List of all of the handlers that are running. Handlers are
						 expected to unregister themselves when they exit. */
};

#endif
