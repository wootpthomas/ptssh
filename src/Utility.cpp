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

#ifndef _PTSSH_UTILITY
#define _PTSSH_UTILITY

#include "Utility.h"

#ifdef WIN32
#  include <winsock2.h>
	//Redefine the close() function on windows so we don't break on linux
#  define close(SOCKET)				closesocket(SOCKET)
#else
#  define SOCKET_ERROR -1
#  include <sys/time.h>
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <errno.h>
#endif

#include <pthread.h>
#include <string.h>
#include <ctype.h>



///////////////////////////////////////////////////////////////////////////////
void 
PTSSH_htons16(uint16 dataIn, uint16 *pDataOut)
{
	*pDataOut = (dataIn << 8) | (dataIn >> 8);
}

///////////////////////////////////////////////////////////////////////////////
void
PTSSH_htons32(uint32 dataIn, uint32 *pDataOut)
{
	*pDataOut = 0;
	*pDataOut |= dataIn << 24;	//Left most byte in place
	*pDataOut |= (dataIn & 0x0000FF00) << 8;
	*pDataOut |= (dataIn & 0x00FF0000) >> 8;
	*pDataOut |= (dataIn >> 24);	//Right most byte in place
}

///////////////////////////////////////////////////////////////////////////////
uint32
PTSSH_htons32(uint32 dataIn)
{
	uint32 dataOut = 0;
	dataOut |= dataIn << 24;	//Left most byte in place
	dataOut |= (dataIn & 0x0000FF00) << 8;
	dataOut |= (dataIn & 0x00FF0000) >> 8;
	dataOut |= (dataIn >> 24);	//Right most byte in place
	return dataOut;
}

///////////////////////////////////////////////////////////////////////////////
uint32
PTSSH_htons32(uint32 *pDataIn)
{
	uint32 dataOut = 0;
	dataOut |= (*pDataIn) << 24;	//Left most byte in place
	dataOut |= ((*pDataIn) & 0x0000FF00) << 8;
	dataOut |= ((*pDataIn) & 0x00FF0000) >> 8;
	dataOut |= ((*pDataIn) >> 24);	//Right most byte in place
	return dataOut;
}

///////////////////////////////////////////////////////////////////////////////
void 
PTSSH_htons64(uint64 dataIn, uint64 *pDataOut)
{
	*pDataOut = 0;
	*pDataOut |= dataIn << 56;	//Left most byte in place
	*pDataOut |= (dataIn & 0x000000000000FF00LL) << 40;
	*pDataOut |= (dataIn & 0x0000000000FF0000LL) << 24;
	*pDataOut |= (dataIn & 0x00000000FF000000LL) << 8;

	*pDataOut |= (dataIn & 0x000000FF00000000LL) >> 8;
	*pDataOut |= (dataIn & 0x0000FF0000000000LL) >> 24;
	*pDataOut |= (dataIn & 0x00FF000000000000LL) >> 40;
	*pDataOut |= (dataIn >> 56);	//Right most byte in place
}

///////////////////////////////////////////////////////////////////////////////
bool 
makeSSHType_string(const char *pStr, uint32 strLen, unsigned char **ppBuf)
{
	if ( *ppBuf)
	{
		delete *ppBuf;
		*ppBuf = NULL;
	}

	if (pStr)
	{
		*ppBuf = new unsigned char[strLen + 4];
		if  ( *ppBuf)
		{
			PTSSH_htons32(strLen, (uint32*)*ppBuf);
			memcpy(*ppBuf +4, pStr, strLen);
			return true;
		}
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
void 
getAbsoluteTime( uint32 microsecFromNow, struct timespec &futureTime)
{
	/* The time between jan 1, 1601 to jan 1, 1970 in 100 nanoseconds
	 * 116444736000000000ns */
	uint64 
		timeBetween = ((uint64) 27111902 << 32) + (uint64) 3577643008;

#if defined(WIN32)
#  if defined(WINCE)
	FILETIME ft;
	SYSTEMTIME st;

	GetSystemTime(&st);
	SystemTimeToFileTime(&st, &ft);
#  else
	FILETIME ft;

	GetSystemTimeAsFileTime(&ft);
#  endif
	//Now convert filetime to timespec...
	//Set seconds
	futureTime.tv_sec = 
		(int32) (( *((uint64*) &ft) - timeBetween) / 10000000);
	//Set nano-seconds
	futureTime.tv_nsec = 
		(int32) (( *((uint64*) &ft) - timeBetween - ((uint64) futureTime.tv_sec * (uint64) 10000000)) * 100);
#else
	/* Linux/Unix */
	if ( gettimeofday( (timeval*) &futureTime, 0) != 0)
	{
		//error
	}
#endif

	/* Add the specified number of microseconds to our timespec
	 * 1 sec  = 1 000 000 000 nanoseconds
	 * 1 msec = 1 000 000 nanoseconds
	 * 1 usec = 1 000 nanoseconds  */
	 //Convert the user-specified microseconds into equivalent nanoseconds 
	futureTime.tv_nsec += microsecFromNow * 1000;
#endif
}

///////////////////////////////////////////////////////////////////////////////
int32
createSocket(int &sock, struct sockaddr_in *pSockAddr, const char* hostAddress, uint16 port, bool bLocalSocket, int connectionsAllowed)
{
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

	pSockAddr->sin_family = AF_INET;
	pSockAddr->sin_port = htons( port );
	
	if (isalpha( hostAddress[0]) )		//Get the IP address and stick that in our "sin"
	{
		// Getting the host by NAME
		struct hostent *remoteHost = gethostbyname( hostAddress );
		if (remoteHost == NULL)
		{
			close(sock);
			return PTSSH_ERR_CouldNotLookupHostName;
		}
		char *ip = inet_ntoa( *(struct in_addr *)*remoteHost->h_addr_list);
		pSockAddr->sin_addr.s_addr = inet_addr(ip);
	}
	else		//Getting the host by IP address
		pSockAddr->sin_addr.s_addr = inet_addr( hostAddress );

	if ( pSockAddr->sin_addr.s_addr == INADDR_NONE) {
		close(sock);
		return PTSSH_ERR_CouldNotLookupIPAddress;
	}

	int result;
	if ( bLocalSocket)
	{
		if (bind(sock, (struct sockaddr*)(pSockAddr), sizeof(struct sockaddr)) == SOCKET_ERROR)
		{
			close(sock);
			return PTSSH_ERR_CouldNotBindSocket;
		}

		/* Now lets create a queue to store pending connection requests
		 * will will only let 5 clients at a time try to connect */
		result = listen(sock, connectionsAllowed);
		if ( result == -1)
		{
			close(sock);
			return PTSSH_ERR_CouldNotListenOnSocket;
		}
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

///////////////////////////////////////////////////////////////////////////////
// Set socket Options... OS specific
#ifdef WIN32
void
setSocketOptions(int sock)
{
	int value = 1;
# ifdef PTSSH_TCP_NODELAY
	if ( setsockopt( sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&value, sizeof(int) ) == SOCKET_ERROR)
	{
//		PTLOG(("[Socket] Error setting socket option: TCP_NODELAY \n"));
	}
# endif

	//Adjust the send and recieve buffers
# ifdef PTSSH_SOCKET_SEND_BUF_SIZE
	value = PTSSH_SOCKET_SEND_BUF_SIZE;
	if ( setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *) &value, sizeof(value)) == SOCKET_ERROR)
	{
//		PTLOG(("[Socket] Error setting socket option: SO_SNDBUF to %d bytes\n", value));
	}
# endif

# ifdef PTSSH_SOCKET_RECV_BUF_SIZE
	value = PTSSH_SOCKET_RECV_BUF_SIZE;
	if ( setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *) &value, sizeof(value)) == SOCKET_ERROR)
	{
//		PTLOG(("[Socket] Error setting socket option: SO_RCVBUF to %d bytes\n", value));
	}
# endif
}
#else /* *nix */

void
setSocketOptions(int sock)
{

}
#endif /* WIN32 */

///////////////////////////////////////////////////////////////////////////////
static const uint8 g_base64Decode[128] = {
	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, //15
	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  62,  0,  0,  0, 63, //31
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,  //47
     0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,  //63
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,  0,  0,  0,  0,  //
     0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,  0,  0,  0,  0,  0,
};
	
///////////////////////////////////////////////////////////////////////////////
int32 decodeBase64(const uint8* pData, const uint32 pDataLen, uint8 **pDataOut, uint32 &pDataOutLen)
{
	uint8
		ctr = 0; //Rolling counter 0 - 3
	uint32
		byteFillNum = 0;

	pDataOutLen = (3 * pDataLen / 4) + 1;
	*pDataOut = new uint8[pDataOutLen];
	if ( ! *pDataOut)
		return PTSSH_ERR_CouldNotAllocateMemory;

	for (uint32 i = 0; i < pDataLen; i++)
	{
		uint8 
			byteToDecode = pData[i],
			decoded;

		//Sanitize to 0 - 127 bits
		if (byteToDecode & 0x80)
			return PTSSH_ERR_InvalidBase64DecodeChar;

		decoded = g_base64Decode[byteToDecode];
		//printf("Decoded: %d\n", decoded);
		switch ( ctr % 4 ){
		case 0:
			(*pDataOut)[byteFillNum] = decoded << 2;
			break;
		case 1:
			(*pDataOut)[byteFillNum++] |= decoded >> 4;
			(*pDataOut)[byteFillNum] = decoded << 4;
			break;
		case 2:
			(*pDataOut)[byteFillNum++] |= decoded >> 2;
			(*pDataOut)[byteFillNum] = decoded << 6;
			break;
		case 3:
			(*pDataOut)[byteFillNum++] |= decoded;
			break;
		}
		
		ctr++;
	}

	pDataOutLen = byteFillNum;

	return PTSSH_SUCCESS;
}
