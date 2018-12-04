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

#ifndef _TCPIPTUNNELHANDLER
#define _TCPIPTUNNELHANDLER

/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"
#include "TunnelHandler.h"
#include <pthread.h>


/*************************
* Forward declarations
*************************/
class PTssh;
class ChannelManager;
class LinkedList;


/**
* This class was designed to handle tunneling between a local socket and a
* ssh channel. It simply transfers data between the local socket and a ssh
* channel.
* This class is used for local tunneling and for X11 tunneling. */
class TcpIpTunnelHandler:
	public TunnelHandler
{
public:

	TcpIpTunnelHandler(PTssh * const pSSH, ChannelManager * const pChannelMgr);
	~TcpIpTunnelHandler(void);

	/* This checks to make sure that we have a valid socket to listen
	 * on, sets some internal variables in the class and then spawns
	 * off a thread that listens for connections on the localSocket.
	 @note Only call ONE init_* function!!!
	 @param[in] localPort Port number to listen on
	 @param[in] totalConnections Specifies the maximum number of connections
		that we will handle at once. Normally this is set to 1. Then when a
		connection is accepted, we service it till that connection either 
		encounters an error or shuts down gracefully. We then go back and
		listen for the next connection.
	 @param[in] callbackFuncPtr When an error occurs or some other event happens
	    with the tunnel that may be of interest to the end developer, this function
		pointer is called to alert some nonPTssh code of the event.
	 @param[in] destAddress When a connection is accepted, this specifies what
		destination address the traffic should be tunneled to
	 @param[in] destPort Specifies destination port
	 @param[in] sourceIPAddress Specifies the origination point of the tunnel
	 @param[in] sourcePort Specifies the originating port of the tunnel
	 @return Returns PTSSH_SUCCESS on successful initialization, otherwise an error code
	 */
	int32 init(
		int localPort,
		int totalConnections,
		int32 (*callbackFuncPtr)(void *ptrStorage),
		const char *destAddress,
		uint16 destPort,
		const char *sourceIPAddress,
		uint16 sourcePort);

	
	void shutdown();

	/**
	* The init() function will create a new thread to listen for connections. This
	* function is that thread. The thread will keep listening and servicing
	* incoming connections until its told to shut down or it encounters a critical
	* error from m_pSSH.
	* When a new connection is accepted, two threads are created to handle the 
	* tunneling from socket -> channel and channel -> socket.
	*/
	void *listenForConnectionsEntry();

	/**
	* When a new incomming connection is detected, this will negotiate a socket and
	* will then spin off two threads to handle the tunneling.
	*/
	bool handleNewConnection();


	/*********************
	* Thread Entry points -> These call the respective class members
	*********************/
	/**
	* The init() function will create a new thread to listen for connections. This
	* function is that thread. The thread will keep listening and servicing
	* incoming connections until its told to shut down or it encounters a critical
	* error from m_pSSH.
	* When a new connection is accepted, two threads are created to handle the 
	* tunneling from socket -> channel and channel -> socket.
	*/
	static void *listenForConnectionsThread(void *pTunnelHandler);

private:

	
	char
		*m_pDestAddress;

	int
		m_boundLocalSocket,
		m_totalConnections;

	int32 
		(*m_pCallbackFuncPtr)(void *ptrStorage);

	uint16
		m_destPort,
		m_sourcePort;
};

#endif
