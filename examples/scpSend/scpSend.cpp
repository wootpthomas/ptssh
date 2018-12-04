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


#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

//http://discuss.joelonsoftware.com/default.asp?design.4.374637.18
#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif


#include "PTsshW.h" //Include the wrapper, we'll use the DLL


/* IF you'd like to time the transfer and see how long it takes,
 * this will enable printing out speed statistics like MB/sec */
#define SHOW_STATISTICS


/************************
* This little example shows how to use the PTssh library/class to send a file
* using Secure Copy (SCP) from your local computer to the remote SSH server
* that you specify. 
***********************/
int main()
{
#ifdef WIN32
	//IF MEMORY_LEAK_DETECTION is defined, memory leaks will be printed out if found
#   if defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
		_CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
#   endif
#endif

	/***********************
	* Modify these values !
	***********************/
	const char *pUsername = "<username>";  //Ex: paul
	const char *pPassword = "<password>";  //Ex: myPassword
	const char *pRemoteAddress = "<ssh address>"; //Ex: 192.168.1.15 -or- your.domain.com
	uint16 pSSHPort = 22;                  //SSH server port number
	const char *pLocalFileToSend = "c:\\msdia80.dll"; //The path to the local file you want to send
	const char *pRemoteFileToWrite = "/mnt/400gig/msdia80.dll"; //Full remote path
    
	
	/***********************
	* Other variables used
	***********************/
	FILE *pFileHandle = NULL;;
	struct stat fileInfo;
	int result;
	bool bIsAuthenticated = false;
	uint32
		cNum = -1,
		optimalSize,
		totalBytesQueued = 0;

#ifdef SHOW_STATISTICS
	clock_t
		start,
		stop;
#endif


	/* Initialize the library. Make sure it returns a success code before 
	 * you continue! */
	PTssh *pSSH = ptssh_create();
	if ( pSSH && ptssh_init(pSSH, pUsername, pRemoteAddress, pSSHPort) != PTSSH_SUCCESS )
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
		ptssh_isAuthSupported(pSSH, PsshAuth_Password, bAuthPassword) != PTSSH_SUCCESS ||
		ptssh_isAuthSupported(pSSH, PsshAuth_HostBased, bAuthHost) != PTSSH_SUCCESS ||
		ptssh_isAuthSupported(pSSH, PsshAuth_PublicKey, bAuthPublicKey) != PTSSH_SUCCESS ||
		ptssh_isAuthSupported(pSSH, PsshAuth_KeyboardInteractive, bAuthKbdInt) != PTSSH_SUCCESS ||
		ptssh_isAuthSupported(pSSH, PsshAuth_None, bAuthNone) != PTSSH_SUCCESS )
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
	if ( ptssh_authByPassword(pSSH, pPassword) != PTSSH_SUCCESS )
	{
		printf("Authentication failed\n");
		ptssh_disconnect(pSSH);
		return -2;
	}


	pFileHandle = fopen(pLocalFileToSend, "rb");
	if ( ! pFileHandle) {
		fprintf(stderr, "Can't local file %s\n", pLocalFileToSend);
		ptssh_disconnect(pSSH);
		return -3;
	}

	//Get the file statistics
	stat(pLocalFileToSend, &fileInfo);
		
	/* Let's initialize the scp stuff. This is like telling the remote server
	 * that we are getting ready to send a file over. We send stats about the file
	 * and other info it needs. If the remote server accepts it all ok, then a
	 * PTSSH_SUCCESS is returned and the channel number is filled with the channel
	 * number to use when writing the file's data via PTssh::channelWrite() */
	result = ptssh_scpSendInit(pSSH, cNum, optimalSize, pRemoteFileToWrite, fileInfo.st_size);
	if ( result == PTSSH_SUCCESS)
	{
		//Everything went ok! The remote SSH server is ready for us to send
		uint32 
			fileSize = (uint32)fileInfo.st_size;
		
		/* If you want to be nice to the library, you can ask for the optimal data
		 * size that you can send on a channel. If you then write to the channel
		 * and keep your channel writes at this size, this will be the most efficient.
		 * Otherwise if a packet is too big, the underlying library will split it, which
		 * will incurr an overhead for allocating memory for a few smaller packets. 
		 * Sending larger or smaller packets doesn't hurt anything, but may not be as fast
		 * and will likely use more CPU power. */
		ptssh_getOptimalDataSize( pSSH, cNum, optimalSize);
		char *pBuf = new char[optimalSize];
		if ( pBuf)
		{
			bool bKeepGoing = true;
			int32 bytesRead = 1;
			//Read the file and send the data over the channel

			printf("Queueing %uMB for sending\n", (fileSize>>20) );
#ifdef SHOW_STATISTICS
			start = clock();
#endif
			while ( bytesRead > 0)
			{
				/* I'm using a C function here for reading the file into
				 * a buffer, obviously you can use any method to get the
				 * data into a buffer */
				bytesRead = fread(pBuf, 1, optimalSize, pFileHandle);

				/* Writing to a channel is normally EXTREMELY quick. Underneath
				 * it all, the pointer to the buffer is wrapped up in a SSH
				 * BinaryPacket and then queued for sending. If there isn't room
				 * in the queue, this function will then block until room is available
				 * or until an error occurs... like the remote end disconnects
				 * unexpectedly. The queue size can be increased if needed
				 * in PTsshConfig.h. Default is about 4MB. This works really well for
				 * gigabit networks while keeping memory usage down. */
				if (bytesRead > 0) 
				{
					result = ptssh_channelWrite(pSSH, cNum, pBuf, bytesRead);
					if ( result != PTSSH_SUCCESS)
					{
						printf("Failed to write channel data. Error %d\n", result);
						break;
					}
					else
					{
						totalBytesQueued += bytesRead;
					}
				}
			}
			fclose(pFileHandle);
			printf("Done queueing %uMB for sending\n", (fileSize>> 20) );

			//Cleanup
			delete pBuf;
			pBuf = NULL;

			/* After you have written (more correctly queued) all the file data to
			 * the specified channel, you must call this function to complete the SCP
			 * transfer. This will block until the last of the file data is dequeued
			 * and sent over the wire and we successfully close the channel. The channel
			 * can not and should NOT be reused for anything else. If you need to SCP
			 * another file, then do another scpSendInit....scpSendFinish as needed. */
			result = ptssh_scpSendFinish(pSSH, cNum);

			if ( result == PTSSH_SUCCESS)
			{
#ifdef SHOW_STATISTICS
				stop = clock();
				
				uint32
					KBs = ((uint32)fileInfo.st_size) >> 10,
					MBs = ((uint32)fileInfo.st_size) >> 20;

				double 
					//elapsedTimeInSec = stop - start,
					elapsedTimeInSec = ((double)(stop - start)) / ((double)CLOCKS_PER_SEC),

					KbytesPerSec = KBs / (elapsedTimeInSec),
					MbytesPerSec = MBs / (elapsedTimeInSec);
				
				printf("SCP transfered %u bytes in %4.2f sec (%4.2fKB/sec %4.2fMB/sec\n",
					fileInfo.st_size, elapsedTimeInSec, KbytesPerSec, MbytesPerSec);
#endif
				printf("SCP transfer success!\n");
			}
			else
				printf("SCP transfer failed\n");
		}
	}

	//Close down our connection gracefully
	printf("[SCP] Sending disconnect msg\n");
	result = ptssh_disconnect(pSSH);
	if ( result != PTSSH_SUCCESS)
	{
		printf("Error shutting down!\n");
		return -4;
	}

	ptssh_destroy( &pSSH);
}
