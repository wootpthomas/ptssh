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

/** Description:
 * To better display the threading goodness that my library provides,
 * this example shows the power of PTssh with multiple threads.
 * A single SSH connection uses one socket for both sending and receiving
 * data. However, with SSH you can have multiple connections that talk
 * over different "channels" on that socket. What this means to you with PTssh
 * is that you can have multiple threads each using their own channel, while the
 * underlying PTssh library will combine and send the data over a single
 * socket in an efficient, thread-safe manner.
 *
 * This example will setup a PTssh instance and then connect up to the SSH
 * server you specify with the given username and password.
 * Then it will setup multiple scp transfers: 8 of which will transfer files
 * from your local machine to the remote machine. Simultaneously, 8 other
 * transfers will be kicked off that will transfer files from the remote
 * machine to this machine.
 *
 * First it will create the local files and fills the files with garbage data.
 * The SHA hash of each file is calculated so that we can verify file
 * integrity after the transfer in the 5th step.
 * 2nd: The first batch of local files are then all simultaneously transfered
 * to the remote host.
 * 3rd: Another batch of local files are generated using garbage data and SHA
 * hashes are calculated.
 * 4th: Simultaneously the local files are transferred to the remote host and
 * the remote files that were transferred over in the 2nd step are transferred
 * back to the local machine. Using two PCs with extremely fast hard drives,
 * CPUs (dual-core+), very efficient NICs (high-end, not onboard POS), and of
 * course a really good switch.
 * 5th: The SHA hashes of all files are then calculated and verified.
 * 6th: The files on the remote and local systems are then deleted.
 * 7th: SHA hashes are all verified.
 */

#include <sys/stat.h>
#include <time.h>
#include <fstream>
#include <stdio.h>
#include <cstdlib>
#include <cstring>



#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

//http://discuss.joelonsoftware.com/default.asp?design.4.374637.18
#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif

#include "PTsshW.h" //Include the wrapper, we'll use the DLL

#include <pthread.h>
 

/* IF you'd like to time the transfer and see how long it takes,
 * this will enable printing out speed statistics like MB/sec */
#define SHOW_STATISTICS
#define NUM_OF_FILES 16  //Make this divisible by 2
#define FILE_SIZE 0x800000 //8MB

//Specify the number of files you want to send
#define NUMBER_OF_FILES_TO_SEND (NUM_OF_FILES/2)
#define SEND_FILE_SIZE FILE_SIZE

#define NUMBER_OF_FILES_TO_RECV (NUM_OF_FILES/2)
#define RECEIVE_FILE_SIZE FILE_SIZE

#define MAX_FILENAME_SIZE 1024


struct threadData{
	PTssh *pSsh;
	char *pFileName;
	uint32 threadID;

	threadData(){
		pSsh = NULL;
		pFileName = NULL;
		threadID = 0;
	}
} TD;

struct threadReturnData{
	int32 result;

	threadReturnData(){
		result = PTSSH_SUCCESS;
	}
} TRD;


static void* threadSend( void *data);
static void* threadRecv( void *data);


/************************
* This little example shows how to use the PTssh library/class to and receive
* multiple files at the same time using Secure Copy (SCP) from your local
* computer to the remote SSH server that you specify. 
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
	const char *pRemoteAddress = "< host address>"; //Ex: 192.168.1.15 -or- your.domain.com
	uint16 pSSHPort = 22;                  //SSH server port number

	/***********************
	* Other variables used
	***********************/
	int result;
	bool bIsAuthenticated = false;

	char *pFilesToSend[NUMBER_OF_FILES_TO_SEND];
	char *pFilesToRecv[NUMBER_OF_FILES_TO_RECV];
	pthread_t
		sendThreads[NUMBER_OF_FILES_TO_SEND],
		recvThreads[NUMBER_OF_FILES_TO_RECV];
	pthread_attr_t attr;

	//Seed our random number generator
	srand( time(NULL));


	//Generate files for sending
	for (int i = 0; i < NUMBER_OF_FILES_TO_SEND; i++)
	{
		pFilesToSend[i] = new char[MAX_FILENAME_SIZE];
		if ( pFilesToSend[i])
		{
			memset( pFilesToSend[i], 0x0, MAX_FILENAME_SIZE);
			sprintf( pFilesToSend[i], "PTssh_send_file%02d.tmp", i);

			FILE *pFH = NULL;
			pFH = fopen( pFilesToSend[i], "wb+");
			if ( pFH)
			{
				//Fill the file to the specified size.
				//I mess with the index variable because rand() isn't random enough
				for (int ctr = 0; ctr < (SEND_FILE_SIZE - i); ctr++)
				{
					unsigned char c = (unsigned char) rand();
					if ( fputc( c, pFH) != c)
					{
						printf("Error writing to file %s\n", pFilesToSend[i]);
						fclose( pFH);
						return -2;
					}
				}
				
				printf("Generated file: %s\n", pFilesToSend[i]);
			}
			fclose(pFH);
		}
		else
		{
			printf("Error generating filename!\n");
			return -1;
		}
	}

	//Generate files for receiving
	for (int i = 0; i < NUMBER_OF_FILES_TO_RECV; i++)
	{
		pFilesToRecv[i] = new char[MAX_FILENAME_SIZE];
		if ( pFilesToRecv[i])
		{
			memset( pFilesToRecv[i], 0x0, MAX_FILENAME_SIZE);
			sprintf( pFilesToRecv[i], "PTssh_recv_file%02d.tmp", i);

			FILE *pFH = NULL;
			pFH = fopen( pFilesToRecv[i], "wb+");
			if ( pFH)
			{
				//I mess with the index variable because rand() isn't random enough
				for (int ctr = 0; ctr < (RECEIVE_FILE_SIZE - i); ctr++)
				{
					unsigned char c = (unsigned char) rand();
					if ( fputc( c, pFH) != c)
					{
						printf("Error writing to file %s\n", pFilesToRecv[i]);
						fclose( pFH);
						return -2;
					}
				}
				
				printf("Generated file: %s\n", pFilesToRecv[i]);
			}
			fclose(pFH);
		}
		else
		{
			printf("Error generating filename!\n");
			return -1;
		}
	}

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

	//Ok, our ssh connection is alive we are ready to begin!

   /* Initialize and set thread detached attribute */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	/* Copy the first set of files to the remote ssh server
	 * We will let each file be sent with a different thread */
	for (int i = 0; i < NUMBER_OF_FILES_TO_RECV; i++)
	{
		int rc;
		struct threadData *pTD = new struct threadData;

		pTD->pSsh = pSSH;
		pTD->pFileName = pFilesToRecv[i];
		pTD->threadID = i +1;

		rc = pthread_create( &sendThreads[i], &attr, threadSend, (void*)pTD );
	}

	//Wait for the files to all be transferred
	for (int i = 0; i < NUMBER_OF_FILES_TO_RECV; i++)
	{
		void *pStatus = NULL;
		int rc = pthread_join( sendThreads[i], &pStatus);
	}

	/*******************************
	* Setup compeleted. Now ready to run stress test!
	*******************************/
	printf("Setup completed! Now running the simultaneous stress test!\n");

	/* Kick off threads for SCP send and SCP receive.
	 * NOTE!!! that we expect the same number for number of files to
	 * send and receive!
	 * Also...
	 * I've found that OpenSSH seems to only allow you to have about
	 * 10 channels opened at once. So what we will do is SCPsend and
	 * SCPreceive two files at once. This should keep us from hitting the
	 * Channel limit, which makes scpInit fail because it can;t open another
	 * channel (limit reached). */
	for (int i = 0; i < NUMBER_OF_FILES_TO_SEND; i++)
	{
		int rc;
		struct threadData *pTD = NULL;
		void *pStatus = NULL;
		
		//SCP Send
		pTD = new struct threadData();
		pTD->pSsh = pSSH;
		pTD->pFileName = pFilesToSend[i];
		pTD->threadID = i;
		rc = pthread_create( &sendThreads[i], &attr, threadSend, (void*)pTD );

		//SCP receive
		pTD = new struct threadData();
		pTD->pSsh = pSSH;
		pTD->pFileName = pFilesToRecv[i];
		pTD->threadID = i + NUMBER_OF_FILES_TO_RECV;
		rc = pthread_create( &recvThreads[i], &attr, threadRecv, (void*)pTD );

		/*****************************
		* Wait for the transfers to finish
		*****************************/
		//SCP Send
		pStatus = NULL;
		rc = pthread_join( sendThreads[i], &pStatus);
		if ( ((struct threadReturnData *)pStatus)->result != PTSSH_SUCCESS)
		{
			printf("Failed to SCPsend %s, result: %d\n",
				pFilesToSend[i], ((struct threadReturnData *)pStatus)->result);
		}

		//SCP receive
		pStatus = NULL;
		rc = pthread_join( recvThreads[i], &pStatus);
		if ( ((struct threadReturnData *)pStatus)->result != PTSSH_SUCCESS)
		{
			printf("Failed to SCPreceive %s, result: %d\n",
				pFilesToRecv[i], ((struct threadReturnData *)pStatus)->result);
		}

	}

	//Close down our connection gracefully
	result = ptssh_disconnect(pSSH);
	if ( result != PTSSH_SUCCESS)
	{
		printf("Error shutting down!\n");
		return -4;
	}

	//Cleanup
	pthread_attr_destroy(&attr);

	for (int i = 0; i < NUMBER_OF_FILES_TO_SEND; i++)
		delete pFilesToSend[i];
	
	for (int i = 0; i < NUMBER_OF_FILES_TO_RECV; i++)
		delete pFilesToRecv[i];

	ptssh_destroy( &pSSH);
}

/********************
* Functions...
********************/
// This is the function that the sending thread begins and ends life in
static void* threadSend( void *data)
{
	struct threadData *pTD = (struct threadData*)data;
	struct threadReturnData *pTRD = new struct threadReturnData();
	uint32 
		optimalDataLen,
		cNum = 0xFFFFFFFF,
		result = PTSSH_SUCCESS;
	int
		bytesRead,
		totalBytesRead = 0;
	char *pBuf = NULL;
	struct stat fileInfo;
	FILE *pFileHandle = fopen(pTD->pFileName, "rb");

	//Get the file statistics
	stat(pTD->pFileName, &fileInfo);

	if (pFileHandle)
	{

#ifdef SHOW_STATISTICS
		clock_t
			start = clock(),
			stop;
#endif
		pTRD->result = ptssh_scpSendInit(pTD->pSsh, cNum, optimalDataLen, pTD->pFileName, fileInfo.st_size);
		if (pTRD->result == PTSSH_SUCCESS)
		{
			printf("Thread %d, channel %d: Initialized transfer of %s to SSH server\n", 
				pTD->threadID, cNum, pTD->pFileName);

			pBuf = new char[optimalDataLen];
			if (pBuf)
			{
				bytesRead = 1;
				while ( bytesRead > 0)
				{
					bytesRead = fread(pBuf, 1, optimalDataLen, pFileHandle);
					
					if (bytesRead > 0) 
					{
						totalBytesRead += bytesRead;
						pTRD->result = ptssh_channelWrite(pTD->pSsh, cNum, pBuf, bytesRead);
						if ( pTRD->result != PTSSH_SUCCESS)
						{
							printf("Thread %d, channel %d: Failed to write channel data. Error %d\n",
								pTD->threadID, cNum, result);
							break;
						}
					}
				}

				pTRD->result = ptssh_scpSendFinish(pTD->pSsh, cNum);
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
				
				printf("Thread %d, channel %d: SCP'd %lu bytes in %.2f sec (%.2fKB/sec %.2fMB/sec\n",
					pTD->threadID, cNum, fileInfo.st_size, elapsedTimeInSec, KbytesPerSec, MbytesPerSec);
#endif
				printf("Thread %d, channel %d: Completed transfer of %s\n",
					pTD->threadID, cNum, pTD->pFileName);

				delete pBuf;
			}
			else
				printf("SCP send-finish failed\n");
		}
		else
			printf("SCP send-init failed\n");

		fclose(pFileHandle);
	}

	delete pTD;
	pTD = NULL;

	pthread_exit( (void*) pTRD);
	return NULL;
}

//Receiving thread
static void* threadRecv( void *data)
{
	struct threadData *pTD = (struct threadData*)data;
	struct threadReturnData *pTRD = new struct threadReturnData();
	uint32 
		cNum = 0xFFFFFFFF,
		recvdBytes = 0,
		result = PTSSH_SUCCESS;
	int
		totalBytesRead = 0;
	char *pBuf = NULL;
	struct stat fileInfo;
	FILE *pFH = NULL;

#ifdef SHOW_STATISTICS
	clock_t
		start,
		stop;
#endif

	/* Now the file that we are going to receive already exists locally and remotely. So first,
	 * we delete the local file. Then we scp it back down */
	if ( remove( pTD->pFileName) != 0)
		printf("Couldn't delete file %s\n", pTD->pFileName);

	pFH = fopen(pTD->pFileName, "wb");
	if (pFH)
	{
#ifdef SHOW_STATISTICS
		start = clock();
#endif
		pTRD->result = ptssh_scpReceiveInit( pTD->pSsh, cNum, fileInfo, pTD->pFileName);
		if (pTRD->result == PTSSH_SUCCESS)
		{
			printf("Thread %d, channel %d: Initialized transfer of %s from SSH server\n", 
				pTD->threadID, cNum, pTD->pFileName);

			while (recvdBytes < (uint32)fileInfo.st_size)
			{
				char *pData = NULL;
				uint32 dataLen = 0;
				/* You can read the data in a variety of ways. Here we choose to use
				 * a blocking read with the default timeout of 0. This will block
				 * until either we get data or the socket disconnects because of an
				 * error. You can specify a timeout value if you wish to have
				 * select-like behavior on a channel. See the documentation for 
				 * PTssh::channelRead for more detailed info. */
				pTRD->result = ptssh_channelRead(pTD->pSsh, cNum, &pData, dataLen, true);
				if ( pTRD->result == PTSSH_SUCCESS)
				{
					if ( pData)
					{
						/* Seems scp likes to give us a Null terminator appended to the end of 
						 * the stream right after the last byte in the file. So if we have
						 * more bytes than we are expecting, don't write the additional byte. */
						if ( (fileInfo.st_size - recvdBytes) < dataLen)
							dataLen = dataLen - 1;

						uint32 len = fwrite( pData, dataLen, 1, pFH);
						if ( len != 1)
						{
							printf("Write file error!\n");
							break;
						}
						else
							recvdBytes += dataLen;

						//You are responsible for deleting any buffers filled by channelRead!
						delete pData;
						pData = NULL;
					}
					else
					{
						//If we get here PTssh has a bug!
						printf("Thread %d, channel %d: Error! No data available\n", pTD->threadID, cNum);
						return NULL;
					}
				}
			}
			
			pTRD->result = ptssh_scpReceiveFinish(pTD->pSsh, cNum);
			if ( pTRD->result == PTSSH_SUCCESS)
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
				
				printf("Thread %d, channel %d: SCP'd %lu bytes in %.2f sec (%.2fKB/sec %.2fMB/sec\n",
					pTD->threadID, cNum, fileInfo.st_size, elapsedTimeInSec, KbytesPerSec, MbytesPerSec);
#endif
				printf("Thread %d, channel %d: completed SCP receive of %s\n",
					pTD->threadID, cNum, pTD->pFileName);
			}
			else
				printf("SCP receive-finish failed\n");
		}
		else
			printf("SCP receive-init failed\n");

		fclose(pFH);
	}

	delete pTD;
	pTD = NULL;

	pthread_exit( (void*) pTRD);
	return NULL;
}
