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
#include <stdlib.h>
#include <fstream>
#include <string.h>


#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

//http://discuss.joelonsoftware.com/default.asp?design.4.374637.18
#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif


#include "PTsshW.h" //Include the wrapper, we'll use the DLL

/***********************
* Defines
***********************/
/* IF you'd like to time the transfer and see how long it takes,
 * this will enable printing out speed statistics like MB/sec */
#define SHOW_STATISTICS
#define TEST_FILE_SIZE   0x9600000   //150MB test file
#define TEMP_BUFFER_SIZE 0x3F000     //252 KB    //OpenSSH's sftp limit is a little under 0x40000


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
	uint16
		pSSHPort = 22;                  //SSH server port number
	const char
		*pUsername = "<username>",  //Ex: paul
		*pPassword = "<password>",  //Ex: myPassword
		*pRemoteAddress = "<host>", //Ex: 192.168.1.15 -or- your.domain.com
		*pLocalFileToSend = "c:\\test\\500MBFile.bin", //The path to the local file you want to create and send
		*pRemoteDirToCreate = "/home/paul/transferTestFirst/",
		*pRemoteDirRenamed = "transferTestSecd",
		*pRemoteFileToWrite = "/mnt/ramdisk/testFile.bin"; //Full remote path
	
	/***********************
	* Other variables used
	***********************/
	FILE *pFH = NULL;
	struct stat 
		fileInfo;
	int result;
	PTSftp 
		*pSftp = NULL;
	SftpFileHandle
		*pSFH = NULL;
	SftpDirHandle
		*pSDH = NULL;
	SFTP_W_ATTR
		attrs;
	uint8
		*pTmpBuf; //4KB temporary buffer

#ifdef SHOW_STATISTICS
	uint32
		KBs,
		MBs;

	double 
		elapsedTimeInSec,
		KbytesPerSec,
		MbytesPerSec;

	clock_t
		start,
		stop;
#endif

	pTmpBuf = new uint8[TEMP_BUFFER_SIZE];
	if ( ! pTmpBuf)
		return -1;
	memset(pTmpBuf, 0x0, TEMP_BUFFER_SIZE);

	//Create local temp file if needed
	if ( stat(pLocalFileToSend, &fileInfo) == 0 && fileInfo.st_size == TEST_FILE_SIZE)
		printf("Skipping creation of temp file\n");
	else
	{
		pFH = fopen(pLocalFileToSend, "wb+");
		if ( pFH)
		{
			printf("Generating file: %s\n", pLocalFileToSend); 
			//Fill the file to the specified size.
			for (int ctr = 0; ctr < TEST_FILE_SIZE; ctr++)
			{
				unsigned char c = (unsigned char) rand();
				if ( fwrite( &c, 1, 1, pFH) != 1)
				{
					printf("Error writing to file %s\n", pLocalFileToSend);
					fclose( pFH);
					return -1;
				}
			}
			
			printf("Generated file: %s\n", pLocalFileToSend);
		}
		fclose(pFH);
		pFH = NULL;
	}

	/* Initialize the library. Make sure it returns a success code before 
	 * you continue! */
	PTssh *pSSH = ptssh_create();
	if ( pSSH && ptssh_init(pSSH, pUsername, pRemoteAddress, pSSHPort) != PTSSH_SUCCESS )
	{
		if (pSSH)
			ptssh_destroy(&pSSH);
		return false;
	}

	ptssh_setLogLevel(pSSH, LL_debug3);

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

	//Authenticate by password
	result = ptssh_authByPassword(pSSH, pPassword);
	if ( result != PTSSH_SUCCESS)
	{
		printf("Authentication failed\n");
		ptssh_disconnect(pSSH);
		return -2;
	}

	//Initialize the SFTP subsystem
	result = ptssh_initSftp(pSSH);
	if ( result != PTSSH_SUCCESS)
	{
		printf("Error init'ing sftp subsystem. Error %d\n", result);
		return -1;
	}

	//Get the sftp object
	pSftp = ptssh_getSftpObj(pSSH);
	if ( ! pSftp)
	{
		printf("Error getting sftp object.\n");
		return -1;
	}

	//First, check and see if the temp directory is there, if it is delete it
	result = ptssh_deleteDir(pSftp, pRemoteDirToCreate);

	//Now create the directory
	//Clear out our attribute object
	memset( &attrs, 0x0, sizeof(SFTP_W_ATTR));
	attrs.permissions =
		FP_USR_RWX | 
		FP_GRP_RWX | 
		FP_OTH_RWX;  //Sets permissions to 0777 (Unix style)
	result = ptssh_makeDir(pSftp, pRemoteDirToCreate, &attrs);
	if ( result != PTSSH_SUCCESS)
	{
		printf("Error making directory %s. Error %d\n", pRemoteDirToCreate, result);
		return -1;
	}

	//Rename the directory
	result = ptssh_renameFileOrDir(pSftp, pRemoteDirToCreate, pRemoteDirRenamed);
	if ( result != PTSSH_SUCCESS)
	{
		printf("Error renaming directory from\n\t%s\n -to-\n\t%s\nError %d\n", 
			pRemoteDirToCreate, pRemoteDirRenamed, result);
		//return -1;
	}

	//Let's write a file to the remote SSH server.
	// 1) Create the file
	result = ptssh_openFile(pSftp, &pSFH, pRemoteFileToWrite, FO_CREATE | FO_RDWR);
	if ( result != PTSSH_SUCCESS)
	{
		printf("Error creating file %s. Error %d\n", pRemoteFileToWrite, result);
		return -1;
	}

	//Open the file we made locally to do our copy tests
	pFH = fopen(pLocalFileToSend, "rb");
	if ( pFH)
	{
		uint32 
			bytesRead = 0;
		uint64
			totalBytesRead = 0;
		stat(pLocalFileToSend, &fileInfo);
#ifdef SHOW_STATISTICS
		start = clock();
#endif
		printf("Using temp bufer size 0x%X (%d)\n", TEMP_BUFFER_SIZE, TEMP_BUFFER_SIZE);
		while ( totalBytesRead < (uint64)fileInfo.st_size)
		{
			bytesRead = fread(pTmpBuf, 1, TEMP_BUFFER_SIZE, pFH);
			if ( bytesRead > 0)
			{
				result = ptssh_writeFile(pSFH, pTmpBuf, bytesRead);
				if ( result != PTSSH_SUCCESS)
				{
					printf("Error writing to file %s. Error %d\n", pRemoteFileToWrite, result);
					return -1;
				}

				totalBytesRead += bytesRead;
			}
		}

		result = ptssh_closeFile(pSftp, &pSFH);
		if ( result != PTSSH_SUCCESS)
		{
			printf("Error closing file %s. Error %d\n", pRemoteFileToWrite, result);
			return -1;
		}
	}

#ifdef SHOW_STATISTICS
	stop = clock();
	
	KBs = ((uint32)fileInfo.st_size) >> 10,
	MBs = ((uint32)fileInfo.st_size) >> 20;

	//elapsedTimeInSec = stop - start,
	elapsedTimeInSec = ((double)(stop - start)) / ((double)CLOCKS_PER_SEC),
	KbytesPerSec = KBs / (elapsedTimeInSec),
	MbytesPerSec = MBs / (elapsedTimeInSec);
	
	printf("SFTP'd %lu bytes in %.2f sec (%.2fKB/sec %.2fMB/sec) to remote SSH server\n",
		fileInfo.st_size, elapsedTimeInSec, KbytesPerSec, MbytesPerSec);
#endif

	ptssh_shutdownSftp(pSSH);

	//Close down our connection gracefully
	result = ptssh_disconnect(pSSH);
	if ( result != PTSSH_SUCCESS)
	{
		printf("Error shutting down!\n");
		return -4;
	}

	ptssh_destroy( &pSSH);
	delete pTmpBuf;
}
