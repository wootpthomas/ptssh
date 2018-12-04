/**************************************************************************
*   Copyright (C) 2009 by Paul Thomas
*   thomaspu@gmail.com
*
*	This file is part of Paul Thomas' SSH class, aka PTssh.
*
*    PTssh is free software: you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation, either version 3 of the License, or
*    (at your option) any later version.
*
*    PTssh is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with PTssh.  If not, see <http://www.gnu.org/licenses/>.
*************************************************************************/


#include <sys/stat.h>
#include <time.h>
#include <fstream>
#include <pthread.h>


#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

//http://discuss.joelonsoftware.com/default.asp?design.4.374637.18
#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif


#ifdef WIN32
#   include <winsock2.h>

	//Redefine the close() function on windows so we don't break on linux
#   define close(SOCKET)				closesocket(SOCKET)
#else
#  define SOCKET_ERROR -1
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <errno.h>
#endif


#include "PTsshW.h" //Include the wrapper, we'll use the DLL


/* IF you'd like to time the transfer and see how long it takes,
 * this will enable printing out speed statistics like MB/sec */
#define SHOW_STATISTICS

/*********************
* Forward declarations
*********************/
struct threadData{
	PTssh *pSSH;
	uint32 cNum;
	int sock;
	pthread_mutex_t
		mutex;			//We use this mutex to safeguard read/write access to bIsSocketAlive

	bool
		bIsSocketAlive; 

	threadData(){
		pSSH = NULL;
		cNum = 0xFFFFFFFF;
		sock = 0xFFFFFFFF;
		bIsSocketAlive = true;
	}
} TD;

struct threadReturnData{
	int32 result;

	threadReturnData(){
		result = PTSSH_SUCCESS;
	}
} TRD;

/**
 * This listens for data on the socket. When it gets data, it writes
 * it to the given SSH channel number. When the socket closes or an error
 * occurs, this thread will exit.
 */
static void * listenSocketThread(void *pThreadData);
/**
 * This listens for data on the channel. When it gets data, it writes
 * it to the given socket number. When the socket closes or an error
 * occurs, this thread will exit. 
 */
static void * listenChannelThread(void *pThreadData);
/**
 * This creates a socket which listens for incoming connections
 */
int32 createSocket(int &sock, const char* hostAddress, uint16 port, int connectionsAllowed);
/**
 * This enables or disables the blocking functionallity on a socket. Please note that
 * you get much better performance using non-blocking sockets.
 */
bool setSocketBlocking(int socket, bool blockingOn);
/**
 * When a new incomming connection is detected, this will negotiate a socket and
 * will then spin off two threads to handle the tunneling.
 */
bool handleNewConnection(PTssh *pSSH, int sock);


/***********************
* Modify these values !
***********************/
const char
	*pUsername = "<username>",  //Ex: paul
	*pPassword = "<password>",  //Ex: myPassword
	*pSSHAddress = "<host>", //Ex: 192.168.1.15 -or- your.domain.com
	*pDestHost = "<destination host>", //Ex: paul.homePC.localdomain
	*pSourceHost = "<source host IP address>"; //Ex: SSH servers IP, 99% of the time, 127.0.0.1 is what you want

uint16
	SSHPort = 6000,          //SSH server port number
	destPort = 3389,      /*This is the port on homePC that we want to "tunnel" to. In
					       * our example, we are setting up a tunnel for windows remote
					       * desktop. So this is the windows remote desktop port number 3389 */
	localSocketNum = 3388;/* This is the local socket that you use, applications connect to this
						   * port. After they successfully connect, any data they send will end
						   * up on the other side of the tunnel: homePC port 3389 */


/************************
* This little example shows how to use the PTssh library/class to create a
* direct TCP/IP "tunnel". The tunnel will let you have a local socket and
* any data that you write to that socket will get forwarded over your SSH
* connection to the destination host.
* For instance, if your home network had a Linux/Unix computer that you could
* SSH into and that SSH computer could talk to PCs behind a firewall, like
* your home computer and you wanted to be able to remotely connect to your home
* PC that can;t be directly accessed, you could setup a TCP/IP tunnel.
*
* You work PC      Home network router/firewall   Home PC
*                           ||               
*     wPC                linuxPC                   homePC
*                           ||               
* After you create the tunnel, you would have a local socket on your work PC
* that you can connect to and any data written on it goes over SSH to
* linuxPC and then that data gets forwarded to homePC. LinuxPC would act as
* a middle-man.
*
* Please note that you do not have to use a socket for tunneling. We just use a
* socket here in this example because it shows how the majority of people will 
* likely use tunneling.
***********************/
int main()
{
#ifdef WIN32
	/* Here we are initializing the Winsock library. You only need to do this
	 * once in your application, even if you use multiple instances of PTssh */
	WSADATA wsadata;
	int sResult = WSAStartup(WINSOCK_VERSION, &wsadata);
	if (sResult)
	{
		printf("Error initializing the windows socket DLL\n");
		return -1;
	}

	//IF MEMORY_LEAK_DETECTION is defined, memory leaks will be printed out if found
#   if defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
		_CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
#   endif
#endif 
	
	/***********************
	* Other variables used
	***********************/
	int 
		result,
		sock;
	bool 
		bIsAuthenticated = false,
		bConnected = false;
	uint32
		cNum = -1,
		totalBytesQueued = 0;

	/* Initialize the library. Make sure it returns a success code before 
	 * you continue! */
	PTssh *pSSH = ptssh_create();
	if ( pSSH && ptssh_init(pSSH, pUsername, pSSHAddress, SSHPort) != PTSSH_SUCCESS )
		return false;

	/* Now make the actual connection to the SSH server. This will create
	 * a socket and negotiate all SSH stuff. If successful, we'll then
	 * be able to authenticate. IF this fails, check the failure code
	 * for more details as to wtf is going on.
	 * The remote address can either be an IPv4 address or a fully qualified
	 * URL:
	 * 127.0.0.1
	 *   -or-
	 * woot.my.sshserver.com  */
	result = ptssh_connect(pSSH);
	if ( result < 0)
	{
		printf("Failed to connect\n" );
		return -1;
	}

#ifdef AUTHENTICATION_TEST
	/* Let's see what authentication methods are allowed by the server. PTssh
	 * supports quite a few */
	bool 
		bAuthPassword = false,
		bAuthHost = false,
		bAuthPublicKey = false,
		bAuthKbdInt = false,
		bAuthNone = false;
	if (
		ptssh_isAuthSupported(pSSH, PTsshAuth_Password, bAuthPassword) != PTSSH_SUCCESS ||
		ptssh_isAuthSupported(pSSH, PTsshAuth_HostBased, bAuthHost) != PTSSH_SUCCESS ||
		ptssh_isAuthSupported(pSSH, PTsshAuth_PublicKey, bAuthPublicKey) != PTSSH_SUCCESS ||
		ptssh_isAuthSupported(pSSH, PTsshAuth_KeyboardInteractive, bAuthKbdInt) != PTSSH_SUCCESS ||
		ptssh_isAuthSupported(pSSH, PTsshAuth_None, bAuthNone) != PTSSH_SUCCESS )
	{
		ptssh_disconnect(pSSH);
		return -1;
	}

	if ( bAuthPassword)
		printf("Server supports authentication by password\n");
	if ( bAuthHost)
		printf("Server supports authentication by host\n");
	if ( bAuthPublicKey)
		printf("Server supports authentication by public key\n");
	if ( bAuthKbdInt)
		printf("Server supports authentication by keyboard interactive login\n");
	if ( bAuthNone)
		printf("Server supports authentication by \"none\" method\n");

#endif /* AUTHENTICATION_TEST */

	//Authenticate by password
	if ( ptssh_authByPassword(pSSH, pPassword) != PTSSH_SUCCESS)
	{
		printf("Authentication failed\n");
		ptssh_disconnect(pSSH);
		return -2;
	}

	//Create the socket and listen for connections
	result = createSocket(sock, pSourceHost, localSocketNum, 1);
	if ( result == PTSSH_SUCCESS)
	{
		//Listen for a connection to the socket
		timeval timeout;
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		/* Create and clear out our fd_set */
		fd_set readfds;
		while ( 1)
		{
			FD_ZERO( &readfds);

			//Add this file descriptor to our list of FDs to check
			FD_SET( sock, &readfds);
			
			//Wait for a process to connect to our local socket
			result = select(sock + 1, &readfds, NULL, NULL,	&timeout);
			if (result < 0)
			{
				printf("Listening Select: encountered an error: %d\n", result);
				break;
			}
			else if ( result > 0)
			{
				if (FD_ISSET( sock, &readfds) )
				{
					//Accept the connection and setup a tunnel
					printf("Client connected, setting up tunnel!\n");
					handleNewConnection( pSSH, sock);
				}
			}
		}

		close(sock);
	}

	//Close down our connection gracefully
	result = ptssh_disconnect(pSSH);
	if ( result != PTSSH_SUCCESS)
	{
		printf("Error shutting down!\n");
		return -4;
	}

	ptssh_destroy( &pSSH);

#ifdef WIN32
	WSACleanup();
#endif
}

///////////////////////////////////////////////////////////////////////////////
/**
* The purpose of this thread is just to sit and listen for data on the socket. When we
* receive data, we immediately write it to the channel. Meanwhile, our main thread is
* handling the other part: When it receives data on the channel, it immediately writes
* it to the socket.
*/
static void* 
listenSocketThread( void *pThreadData)
{
	struct threadData *pTD = (struct threadData*)pThreadData;
	struct threadReturnData *pTRD = new struct threadReturnData();

	//As long as the socket is alive, keep reading date off of it and write it to the channel
	bool
		bConnected = true;
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
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	while (bConnected)
	{
		FD_ZERO( &readfds);

		//Add this file descriptor to our list of FDs to check
		FD_SET( pTD->sock, &readfds);
		
		//Wait for a process to connect to our local socket
		result = select(pTD->sock + 1, &readfds, NULL, NULL, &timeout);
		if (result < 0)
		{
			printf("[LT] encountered an error: %d\n", result);
			bConnected = false;
			pTRD->result = result;
		}
		else if ( result > 0)
		{
			/* yay! Theres data available to be read from the socket
			 * Read the data off and pass it on to PTssh */
			do {
				bytesRead = recv( pTD->sock, buf, 1024, 0);

				//Check for error. If WSAEWOULDBLOCK, then theres no further data available from the socket
				if ( bytesRead <= 0 )
				{
					if ( bytesRead == 0)
						printf("[LT] Socket disconnected\n");
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
						printf("[LT] Encountered an error during recv() and is shutting down! Error %d\n", error);
						bConnected = false;
						pTRD->result = error;

						/* Set the shared variable so that the next time our listenChannelThread
						 * checks the socket status, it'll know its dead */
						pthread_mutex_lock( &pTD->mutex);
							pTD->bIsSocketAlive = false;
						pthread_mutex_unlock( &pTD->mutex);
					}
				}
				else
				{
					result = ptssh_channelWrite( pTD->pSSH, pTD->cNum, (const char *)&buf, bytesRead);
					if ( result != PTSSH_SUCCESS)
					{
						printf("[LT] Error while writing to PTssh: %d\n", result);
						bConnected = false;
						pTRD->result = result;
					}
					//else
					//	printf("[LT] Socket -> channel %d bytes\n", bytesRead);
				}

			} while (bytesRead > 0);
		}
		else
			continue;
	}

	printf("[LT] Thread exiting!\n");
	pthread_exit( (void*)pTRD);
	return (void*)pTRD;
}

///////////////////////////////////////////////////////////////////////////////
static void *
listenChannelThread(void *pThreadData)
{
	struct 
		threadData *pTD = (struct threadData*)pThreadData;
	struct 
		threadReturnData *pTRD = new struct threadReturnData();
	int 
		error = 0,
		result;
	uint32
		dataLen = 0;
	char 
		*pData = NULL;
	bool 
		bKeepGoing = true;

	//Go into writing loop
	while (bKeepGoing)
	{
		//Listen for 1msec
		result = ptssh_channelRead(pTD->pSSH, pTD->cNum, &pData, dataLen, true, 1000);
		if ( result == PTSSH_SUCCESS)
		{
			int 
				bytesSent = 0,
				totalSent = 0;
			//printf("[LC] Channel -> socket %d bytes\n", dataLen);

			do {
				//Write the data to the socket
				bytesSent = send(pTD->sock, pData + totalSent, dataLen - totalSent, 0);

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
						continue;
					}
					else
					{
						printf("[LC] Socket sending error %d!\n", error);
						bKeepGoing = false;
						break;
					}
				}
				else
					totalSent += bytesSent;

			} while (bytesSent > 0 && totalSent < dataLen);

			if ( bytesSent != dataLen)
				bKeepGoing = false;
		}
		else if (result == PTSSH_ERR_NoDataAvailable)
		{
			/* Now heres the thing, since we are listening on the SSH channel, we won't
			 * immediately know when the tunnel has died as a result of the socket closing
			 * or a socket error occuring. So we depend on the thread that's listening
			 * on the socket to let us know through a shared variable if the socket is
			 * still alive */
			pthread_mutex_lock( &pTD->mutex);
				if ( ! pTD->bIsSocketAlive)
				{
					//Socket is dead, exit next time through our loop
					bKeepGoing = false;
				}
			pthread_mutex_unlock( &pTD->mutex);
		}
		else
		{
			bKeepGoing = false;
			printf("[LC] Channel read failure, exiting. Error %d\n", result);
		}
	}

	printf("[LC] Thread exiting!\n");
	pthread_exit( (void*)pTRD);
	return (void*)pTRD;
}

///////////////////////////////////////////////////////////////////////////////
int32
createSocket(int &sock, const char* hostAddress, uint16 port, int connectionsAllowed)
{
	struct sockaddr_in sin;
	int32 result = PTSSH_SUCCESS;

	//Let's get our socket ready
	sock = socket(PF_INET, SOCK_STREAM, 0);

#ifdef WIN32
	if (sock  == INVALID_SOCKET)
#else
	if (sock < 0)
#endif
	{
		return -1;
	}

#ifndef WIN32
	fcntl(sock , F_SETFL, 0);
#endif
	sin.sin_family = AF_INET;
	sin.sin_port = htons( port );
	
	if (isalpha( hostAddress[0]) )		//Get the IP address and stick that in our "sin"
	{
		// Getting the host by NAME
		struct hostent *remoteHost = gethostbyname( hostAddress );
		if (remoteHost == NULL)
		{
			close(sock);
			return -1;
		}
		char *ip = inet_ntoa( *(struct in_addr *)*remoteHost->h_addr_list);
		sin.sin_addr.s_addr = inet_addr(ip);
	}
	else		//Getting the host by IP address
		sin.sin_addr.s_addr = inet_addr( hostAddress );

	if ( sin.sin_addr.s_addr == INADDR_NONE) {
		close(sock);
		return -1;
	}

	if (bind(sock, (struct sockaddr*)(&sin), sizeof(sin)) == SOCKET_ERROR)
	{
		close(sock);
		return -1;
	}

	/* Now lets create a queue to store pending connection requests
	 * will will only let 5 clients at a time try to connect */
	result = listen(sock, connectionsAllowed);
	if ( result == -1)
	{
		close(sock);
		return -1;
	}

	return PTSSH_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
bool 
setSocketBlocking(int socket, bool blockingOn)
{
	//Important: Let's make the socket non-blocking
#ifdef WIN32
	u_long iMode;
	if (blockingOn)
		iMode = 1;
	else
		iMode = 0;

	if (ioctlsocket(socket, FIONBIO, &iMode) == 0)
		return true;

	return false;
#else
	int x = fcntl(socket, F_GETFL, 0);         // Get socket flags;
	if (blockingOn)
	{
		//blocking
		x &= (~ O_NONBLOCK);	//Mask off the non-blocking flag
	}
	else
	{
		// Non-blocking
		x |= O_NONBLOCK;
	}

	if (fcntl(socket, F_SETFL , x) == 0)
		return true;

	return false;
#endif

}

////////////////////////////////////////////////////////////////////////////////////
bool
handleNewConnection(PTssh *pSSH, int sock)
{
	int32
		result;
	uint32
		cNum = 0xFFFFFFFF;
	struct sockaddr_in 
		*pClientAddress = new sockaddr_in;
	int
		len = sizeof(*pClientAddress),
#ifdef WIN32
		tunnelSock = accept( sock, (sockaddr*) pClientAddress, &len);
#else
		tunnelSock = accept( sock, (sockaddr*) pClientAddress, (socklen_t*)&len);
#endif
	if ( tunnelSock < 0)
	{
		printf("Accepting an incoming socket errored with code %d\n", tunnelSock);
		return false;
	}

	if ( ! setSocketBlocking(tunnelSock, false) )
		printf("Could not set socket blocking!\n");

	//We have negotiated a socket. Let's create a channel to use for the tunnel
	result = ptssh_createChannel_directTCPIP(pSSH, cNum, pDestHost, destPort, pSourceHost, SSHPort);
	if ( result == PTSSH_SUCCESS)
	{
		//Ok, the socket has been negotiated and the channel created. Start forwarding traffic!
		struct threadData 
			*pTD = new struct threadData();  //We'll let both threads share it. Ok as long as both only read
		if ( pTD)
		{
			struct threadReturnData
				*pTRDListenSocket = NULL,
				*pTRDListenChannel = NULL;
			pthread_attr_t 
				threadAttr;
			pthread_t
				threadSocketObj,
				threadChannelObj;
			void
				*pThreadSocketStatus = NULL,
				*pThreadChannelStatus = NULL;
			int
				rc;
			
			pthread_attr_init( &threadAttr);
			pthread_attr_setdetachstate(&threadAttr, PTHREAD_CREATE_JOINABLE);
			
			//Fill in the data we give to each thread
			pTD->cNum = cNum;
			pTD->pSSH = pSSH;
			pTD->sock = tunnelSock;
			pthread_mutex_init( &pTD->mutex, 0);

			//Create threads to handling forwarding the data
			rc = pthread_create( &threadSocketObj, &threadAttr, listenSocketThread, (void*)pTD);
			rc = pthread_create( &threadChannelObj, &threadAttr, listenChannelThread, (void*)pTD);

			//Status
			printf("****************\nTunnel is alive!\n****************\n");

			//Wait for the tunnel to be closed or a socket error: causes threads to exit
			pthread_join( threadSocketObj, &pThreadSocketStatus);
			pthread_join( threadChannelObj, &pThreadChannelStatus);

			//Status
			printf("****************\nTunnel shutting down\n****************\n");

			//cleanup
			pthread_attr_destroy( &threadAttr);

			//Inspect thread exit data... and delete when finished
			delete pThreadSocketStatus;
			delete pThreadChannelStatus;

			//Close the channel we used
			result = ptssh_closeChannel(pSSH, cNum);
			//Delete the channel

			pthread_mutex_destroy( &pTD->mutex);
			delete pTD;
		}
	}

	return true;
}