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

/* IF you'd like to time the transfer and see how long it takes,
 * this will enable printing out speed statistics like MB/sec */
#define SHOW_STATISTICS



#include <sys/stat.h>
#include <fstream>
#include <string.h>

#ifdef SHOW_STATISTICS
#  include <time.h>
#endif



#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

//http://discuss.joelonsoftware.com/default.asp?design.4.374637.18
#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif

#include "PTsshConfig.h"
#include "PTssh.h"
#include "PTSftp.h"
#include "SftpFileHandle.h"
#include "SftpDirHandle.h"



/************************
* This little example shows how to use the PTssh library/class to send a file
* using Secure Copy (SCP) from your local computer to the remote SSH server
* that you specify. 
***********************/
int main()
{
#ifdef PTSSH_SFTP
	/***********************
	* Modify these values !
	***********************/
	const char
		*pUsername = "<username>",  //Ex: paul
		*pPassword = "<password>",  //Ex: myPassword
		*pRemoteAddress = "<host>", //Ex: 192.168.1.15 -or- your.domain.com
		*pOpenDir = "/home/paul/",
		//*pLocalFileToSend = "c:\\install.exe", //The path to the local file you want to send
		//*pRemoteFileToWrite = "/mnt/400gig/ramdisk/install.exe", //Full remote path
		//*pFilename = "/home/paul/PTssh_recv_file00.tmp";
		//*pFilename = "/mnt/ramdisk/movie.avi";
		*pFilename = "/home/paul/movie.avi";
	uint16
		pSSHPort = 22;                  //SSH server port number


#ifdef SHOW_STATISTICS
	clock_t
		start,
		stop;
#endif

	/***********************
	* Other variables used
	***********************/
	int result;
	bool bIsAuthenticated = false;
	uint32
		cNum = -1,
		//optimalSize,
		totalBytesQueued = 0;
	PTSftp
		* pSftp = NULL;
	SftpFileHandle
		*pSftpFileHandle = NULL;

#ifdef WIN32
	//IF MEMORY_LEAK_DETECTION is defined, memory leaks will be printed out if found
#   if defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
		_CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
#   endif
#endif

	/* Initialize the library. Make sure it returns a success code before 
	 * you continue! */
	PTssh *pPTssh = new PTssh();
	if ( pPTssh && pPTssh->init(pUsername, pRemoteAddress, pSSHPort) != PTSSH_SUCCESS )
		return false;

	//Set the logging level
	pPTssh->setLogLevel(LL_debug3);

	/* Now make the actual connection to the SSH server. This will create
	 * a socket and negotiate all SSH stuff. If successful, we'll then
	 * be able to authenticate. IF this fails, check the failure code
	 * for more details as to wtf is going on.
	 * The remote address can either be an IPv4 address or a fully qualified
	 * URL:
	 * 127.0.0.1
	 *   -or-
	 * woot.my.sshserver.com  */
	result = pPTssh->connectUp();
	if ( result < 0)
	{
		printf("Failed to connect\n" );
		return -1;
	}

	//Authenticate by password
	result = pPTssh->authByPassword(pPassword);
	if ( result != PTSSH_SUCCESS)
	{
		printf("Authentication failed\n");
		pPTssh->disconnect();
		return result;
	}

	result = pPTssh->initSFTP();
	if ( result != PTSSH_SUCCESS)
	{
		printf("Failed to init SFTP stuff. Error %d\n", result);
		return result;
	}

	pSftp = pPTssh->getSftpObj();
	if ( pSftp)
	{
		uint32
			bytesRead = 0,
			bufLen = 0;
		uint8 
			*pBuf = NULL;
		SftpAttrs
			attrs;
		SftpDirHandle 
			*pSftpDirHandle = NULL;

		printf("SFTP object created!\n");

		//Let's get the contents of the current home directory
		result = pSftp->openDir( &pSftpDirHandle, pOpenDir);
		if ( result == PTSSH_SUCCESS && pSftpDirHandle)
		{
			DirectoryItem *pDI = NULL;
			uint32 items = 0;
			result = pSftpDirHandle->readDir(&pDI, items);
			if ( result == PTSSH_SUCCESS)
			{
				printf("Recieved a total of %d items in the directory\n", items);
				printf("Listing directory contents with \"long\" file names\n");
				for (uint32 i = 0; i < items; i++)
				{
					printf("%3d: %s\n", items, pDI[i].pLongFileName);
				}

				if ( items > 1)
					delete [] pDI;
				else
					delete pDI;
				pDI = NULL;
			}
			else
				printf("Error %d trying to read directory %s\n", result, pOpenDir);

			result = pSftp->closeDir( &pSftpDirHandle);
			if ( result != PTSSH_SUCCESS)
				printf("Error %d trying to close directory handle to %s\n", result, pOpenDir);
		}
		else
		{
			printf("Error %d trying to open directory %s\n", result, pOpenDir);
		}

		result = pSftp->openFile( &pSftpFileHandle, pFilename, FO_RDONLY);
		if ( result != PTSSH_SUCCESS)
		{
			printf("Error %d opening %s\n", result, pFilename);
			return -3;
		}

		result = pSftpFileHandle->getFileAttributes( &attrs);
		if ( result != PTSSH_SUCCESS)
		{
			printf("Error %d getting file stats for %s\n", result, pFilename);
			return -7;
		}

		//Create a buffer big enough to hold the file
		pBuf = new uint8[ (uint32)attrs.fileSize()];
		if (! pBuf)
			return -1;

		bufLen = (uint32)attrs.fileSize();
		memset(pBuf, 0x0, bufLen);

#ifdef SHOW_STATISTICS
		start = clock();
#endif

		result = pSftpFileHandle->read(pBuf, bufLen, 0, bytesRead);
		if ( result != PTSSH_SUCCESS)
		{
			printf("Error %d while trying to read %s\n", result, pFilename);
			return -5;
		}
		printf("Read %d bytes\n", bytesRead);

#ifdef SHOW_STATISTICS
		{
			stop = clock();
			
			uint32
				KBs = ((uint32)bufLen) >> 10,
				MBs = ((uint32)bufLen) >> 20;

			double 
				//elapsedTimeInSec = stop - start,
				elapsedTimeInSec = ((double)(stop - start)) / ((double)CLOCKS_PER_SEC),

				KbytesPerSec = KBs / (elapsedTimeInSec),
				MbytesPerSec = MBs / (elapsedTimeInSec);
			
			printf("SFTP transfered %u bytes in %4.2f sec (%4.2fKB/sec %4.2fMB/sec\n",
				bufLen, elapsedTimeInSec, KbytesPerSec, MbytesPerSec);
		}
#endif

		FILE *pFH = fopen("c:\\test\\movie.avi", "w");
		if ( pFH)
		{
			fwrite( pBuf, bytesRead, 1, pFH);
			fclose( pFH);
		}

		delete pBuf;
		pBuf = 0;

		result = pSftp->closeFile( &pSftpFileHandle);
		if ( result != PTSSH_SUCCESS)
		{
			printf("Error %d closing file %s\n", result, pFilename);
			return -4;
		}


		pPTssh->shutdownSftp();
	}

	//Close down our connection gracefully
	result = pPTssh->disconnect();
	if ( result != PTSSH_SUCCESS)
	{
		printf("Error shutting down!\n");
		return -4;
	}

	delete pPTssh;
	pPTssh = NULL;
#else
	printf("PTssh was not built with SFTP support\n");
	return 0;
#endif /* PTSSH_SFTP */
}
