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
#ifndef _PTSSHUTILITY
#define _PTSSHUTILITY

#include "PTsshConfig.h"

/************************
* Forward Declarations
************************/


/**
* This is a collection of utility functions
*/

/**
* Translates the given uint16 from host order to network order
*/
void PTSSH_htons16(uint16 dataIn, uint16 *pDataOut);

/**
* Translates the given uint32 from host order to network order. This is a tad
* quicker than the one below it. 
*/
void PTSSH_htons32(uint32 dataIn, uint32 *pDataOut);

/**
* Translates the given uint32 from host order to network order. This method is
* provided for convience. 
*/
uint32 PTSSH_htons32(uint32 dataIn);
uint32 PTSSH_htons32(uint32 *pDataIn);

/**
* Translates the given uint64 from host order to network order.  
*/
void PTSSH_htons64(uint64 dataIn, uint64 *pDataOut);

/**
* Given a char* and its size, this will allocate a buffer big enough
* to hold the SSH string type -> size (4) + char* (length )
*/
bool makeSSHType_string(const char *pStr, uint32 strLen, unsigned char **ppBuf);

/**
 * SSH data types
 */
struct ssh_mpint {
	uint32 len;
	uint8 data;
};

struct ssh_string {
	uint32 len;
	uint8 data;
};


/**
* This function gets the current time as a struct timespec and then adjusts
* it to the future time by adding on the requested number of microseconds.
* The timespec is then a absolute future time.
* Useful when you need to give one of the pthreads-related functions a
* timspec to use for a timeout value.
*/
void getAbsoluteTime( uint32 microsecFromNow, struct timespec &futureTime);

/**
 * This just wrapps up the two methods that we use to create sockets. We either
 * create a remote socket (PTssh connecting to remote host) or we create a local
 * socket (when we do tunneling) 
 */
int32 createSocket(
	int &sock,
	struct sockaddr_in *pSockAddr,
	const char* hostAddress,
	uint16 port,
	bool bLocalSocket,
	int connectionsAllowed = 1);



/**
 * This enables or disables the blocking functionallity on a socket. Please note that
 * you get much better performance using non-blocking sockets.
 */
bool setSocketBlocking(int socket, bool blockingOn);

/**
 * Sets the socket options as they have been #defined in the PTsshConfig.h file
 */
void setSocketOptions(int sock);

/**
* Decodes a string that is encoded in base64
*/
int32 decodeBase64(const uint8* pData, const uint32 pDataLen, uint8 **pDataOut, uint32 &pDataOutLen);


#endif
