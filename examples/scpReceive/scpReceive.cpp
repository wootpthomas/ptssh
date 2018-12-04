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
* This little example shows how to use the PTssh library/class to get a file
* using Secure Copy (SCP) from the remote SSH server that you specify to
* your local computer.
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
	const char
		*pUsername = "<username>",  //Ex: paul
		*pPassword = "<password>",  //Ex: myPassword
		*pRemoteAddress = "<ssh address>"; //Ex: 192.168.1.15 -or- your.domain.com
	uint16 pSSHPort = 22;                  //SSH server port number
	const char *pLocalFileToWrite = "c:\\recvd_movie.avi"; //The path to the local file we will write
	const char *pRemoteFileToGet = "/mnt/ramdisk/movie.avi"; //Full remote path of file to get
    
	
	/***********************
	* Other variables used
	***********************/
	FILE *pFileHandle = NULL;;
	struct stat fileInfo;
	int result;
	bool bIsAuthenticated = false;
	uint32
		cNum = -1,
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
	if ( ptssh_authByPassword(pSSH, pPassword) != PTSSH_SUCCESS)
	{
		printf("Authentication failed\n");
		ptssh_disconnect(pSSH);
		return -2;
	}


	pFileHandle = fopen( pLocalFileToWrite, "wb");
	if ( pFileHandle)
	{
		uint64
			recvdBytes = 0;
		
#ifdef SHOW_STATISTICS
			start = clock();
#endif
		if ( ptssh_scpReceiveInit(pSSH, cNum, fileInfo, pRemoteFileToGet) == PTSSH_SUCCESS)
		{
			while (recvdBytes < fileInfo.st_size)
			{
				char *pData = NULL;
				uint32 dataLen = 0;
				/* You can read the data in a variety of ways. Here we choose to use
				 * a blocking read with the default timeout of 0. This will block
				 * until either we get data or the socket disconencts because of an
				 * error. You can specify a timeout value if you wish to have
				 * select-like behavior on a channel. See the documentation for 
				 * PTssh::channelRead for more detailed info */
				if ( ptssh_channelRead(pSSH, cNum, &pData, dataLen, true) == PTSSH_SUCCESS)
				{
					if ( pData)
					{
						/* Seems scp likes to give us a Null terminator appended to the end of 
						 * the stream right after the last byte in the file. So if we have
						 * more bytes than we are expecting, don't write the additional byte. */
						if ( (fileInfo.st_size - recvdBytes) < dataLen)
							dataLen = dataLen - 1;

						uint32 len = fwrite( pData, dataLen, 1, pFileHandle);
						if ( len != 1)
						{
							printf("Write file error!\n");
							break;
						}
						else
						{
							recvdBytes += dataLen;
							
							//printf("[main] Got %d (%d/%d%d) bytes\n", 
							//	dataLen, recvdBytes, fileInfo.st_size, fileInfo.st_size);
						}

						//You are responsible for deleting any buffers filled by channelRead!
						delete pData;
						pData = NULL;
					}
					else
					{
						//If we get here PTssh has a bug!
						printf("Error! No data available\n");
						return -4;
					}
				}
			}
			
			if ( ptssh_scpReceiveFinish(pSSH, cNum) == PTSSH_SUCCESS)
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
				
				printf("SCP received %u bytes in %4.2f sec (%4.2fKB/sec %4.2fMB/sec\n",
					fileInfo.st_size, elapsedTimeInSec, KbytesPerSec, MbytesPerSec);
#endif
				printf("SCP receive successful!\n");
			}
			else
				printf("SCP receive-finish failed\n");
		}
		else
			printf("SCP receive-init failed\n");

		fclose(pFileHandle);
	}
	else
	{
		printf("Couldn't create local file %s\n", pLocalFileToWrite);
	}

	//Close down our connection gracefully
	result = ptssh_disconnect(pSSH);
	if ( result != PTSSH_SUCCESS)
	{
		printf("Error shutting down!\n");
		return -4;
	}

	ptssh_destroy( &pSSH);
}







