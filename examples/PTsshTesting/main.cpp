



/* This is the main file thats primarily just used to help test
* Paul's SSH Class (PTssh) */

/************************
* Define the types of tests to run
***********************/
//#define EXEC_TEST
//#define SCP_SEND_TEST
//#define SCP_RECEIVE_TEST
//#define TERMINAL_TEST
//#define AUTHENTICATION_TEST
//#define PTSSH_FTP 
//#define REMOTE_PORT_FORWARD
#define X11_TEST
//#define PUBLIC_KEY_TEST




#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <fstream>
#include <string.h>

#ifdef X11_TEST
#  include <signal.h>
#endif


#ifdef PUBLIC_KEY_TEST  //Define only ONE below
#  define PUBLIC_KEY_TEST_RSA_KEY
//#  define PUBLIC_KEY_TEST_DSS_KEY
#endif

#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

//http://discuss.joelonsoftware.com/default.asp?design.4.374637.18
#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif


#include "PTssh.h"
#include "Data.h"



// Generated by BreakPoint Software's Hex Workshop v5.1.4.4188
//   http://www.hexworkshop.com

int g_RsaPublicKeySize = 199;
unsigned char g_RsaPublicKey[199] =
{
    0x41, 0x41, 0x41, 0x41, 0x42, 0x33, 0x4E, 0x7A, 0x61, 0x43, 0x31, 0x79, 0x63, 0x32, 0x45, 0x41, 
 
} ;


int g_RsaPrivateKeySize = 452;
unsigned char g_RsaPrivateKey[452] =
{
    0x41, 0x41, 0x41, 0x41, 0x67, 0x51, 0x43, 0x4A, 0x38, 0x61, 0x72, 0x67, 0x2F, 0x6C, 0x71, 0x33, 
 
} ;



int g_DssPrivateKeyLen = 34;
unsigned char g_DssPrivateKey[34] =
{
    0x41, 0x41, 0x41, 0x41, 0x46, 0x51, 0x43, 0x4A, 0x61, 0x64, 0x59, 0x6B, 0x69, 0x63, 0x30, 0x4F, 

} ;



int g_DssPublicKeyLen = 578;
unsigned char g_DssPublicKey[578] =
{
    0x41, 0x41, 0x41, 0x41, 0x42, 0x33, 0x4E, 0x7A, 0x61, 0x43, 0x31, 0x6B, 0x63, 0x33, 0x4D, 0x41, 

} ;


#ifdef REMOTE_PORT_FORWARD
	const char
		*g_pRemotePortForwardAddr ="0.0.0.0";
	uint16
		g_remotePortForwardPort = 3389;

static void g_callbackFunc(struct PTsshCallBackData* pData)
{
	Data *pDataClass = NULL;
	PTLOG(("Woot! Callback func called!\n"));

	//Cast our PTssh object
	PTssh *ptssh = (PTssh*) pData->pPTsshObject;

	//Now we can read and write from the tunnel as we please
	ptssh->channelRead(pData->channelNumber, &pDataClass);

	delete pDataClass;

	ptssh->closeChannel(pData->channelNumber);
}
#endif

#ifdef X11_TEST
//Global to help catch signals
bool g_bKeepRunning = true;

void shutdown(int sig);
#endif

const char 
	*g_pUsername = "<user>",
	*g_pHostAddr = "<address>", //192.168.1.50
	*g_pPassword = "<password>";
uint16
	g_port = 22;

/************************
* The goodz
***********************/
int main()
{
#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	_CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
#endif


#ifdef SCP_SEND_TEST
	//const char *pLocalFile = "c:\\bigFile.rar";
	//const char *pRemoteFileToGet = "/tmp/ramdisk/bigFile.rar";
	//const char *pLocalFile = "c:\\WinXP_SP3_student.iso";
	//const char *pRemoteFileToGet = "/mnt/400gig/ramdisk/WinXP_SP3_student.iso";
	const char *pLocalFile = "c:\\test\\openSolaris.iso";
	const char *pRemoteFileToGet = "/mnt/400gig/ramdisks/openSolaris.iso";
    FILE *pFileHandle = NULL;;
	struct stat fileInfo;
#endif /* SCP_SEND_TEST */

#ifdef SCP_RECEIVE_TEST
	const char *pRemoteFileRecv = "/mnt/400gig/ramdisk/ptssh_10400KB.exe";
	const char *pLocalFileName = "c:\\recvd_ptssh_10400KB.exe";
	//const char *pRemoteFileRecv = "/mnt/400gig/ramdisk/install.exe";
	//const char *pLocalFileName = "c:\\recvd_install.exe";
	//const char *pRemoteFileRecv = "/mnt/400gig/ramdisk/WinXP_SP3_student.iso";
	//const char *pLocalFileName = "c:\\recvd_WinXP_SP3_student.iso";
	//const char *pRemoteFileRecv = "/mnt/400gig/ramdisk/pscp.exe";
	//const char *pLocalFileName = "c:\\recvd_pscp.exe";
	FILE *pRecvFileHandle = NULL;
#endif /* SCP_RECEIVE_TEST */

#ifdef X11_TEST
	//Setup our signal handler to catch CTRL + C
	(void) signal(SIGTERM, shutdown);
	(void) signal(SIGINT, shutdown);
#endif


	/* Whenever you connect to a SSH server, you know the server's
	* address and port, so why not expect it in the constructor? */

	PTssh ptssh;
	if ( ptssh.init(g_pUsername, g_pHostAddr, g_port) != PTSSH_SUCCESS )
		return false;

	//Let's set the logging level
	if ( ptssh.setLogLevel(LL_debug3) != PTSSH_SUCCESS)
		return false;

	/* Its kinda nice to be able to connect on command */
	int result = ptssh.connectUp();
	if ( result < 0)
	{
		printf("Failed to connect\n" );
		return 1;
	}

	//Print out the server's host key
	uint8 *pHostKey = NULL;
	uint32 hostKeyLen = 0;
	result = ptssh.getServerHostKey( &pHostKey, hostKeyLen);
	if ( result != PTSSH_SUCCESS)
	{
		printf("Failed to get server's host key\n");
		return 2;
	}

	printf("Server's host key fingerprint:\n");
	for (uint32 i = 0; i < hostKeyLen; i++)
	{
		printf("%02X ", pHostKey[i] );
	}
	printf("\n");
	delete pHostKey;
	pHostKey = NULL;
	hostKeyLen = 0;
		

#ifdef AUTHENTICATION_TEST
	//Let's see what authentication methods are allowed
	bool 
		bAuthPassword = false,
		bAuthHost = false,
		bAuthPublicKey = false,
		bAuthKbdInt = false,
		bAuthNone = false;
	if (
		ptssh.isAuthSupported(PTsshAuth_Password, bAuthPassword) != PTSSH_SUCCESS ||
		ptssh.isAuthSupported(PTsshAuth_HostBased, bAuthHost) != PTSSH_SUCCESS ||
		ptssh.isAuthSupported(PTsshAuth_PublicKey, bAuthPublicKey) != PTSSH_SUCCESS ||
		ptssh.isAuthSupported(PTsshAuth_KeyboardInteractive, bAuthKbdInt) != PTSSH_SUCCESS ||
		ptssh.isAuthSupported(PTsshAuth_None, bAuthNone) != PTSSH_SUCCESS )
	{
		ptssh.disconnect();
		return -1;
	}

	if ( bAuthPassword)
		PTLOG(("Server supports authentication by password\n"));
	if ( bAuthHost)
		PTLOG(("Server supports authentication by host\n"));
	if ( bAuthPublicKey)
		PTLOG(("Server supports authentication by public key\n"));
	if ( bAuthKbdInt)
		PTLOG(("Server supports authentication by keyboard interactive login\n"));
	if ( bAuthNone)
		PTLOG(("Server supports authentication by \"none\" authentication\n"));

#endif /* AUTHENTICATION_TEST */


#ifdef PUBLIC_KEY_TEST_RSA_KEY
	result = ptssh.authByPublicKey( 
		(const char *)g_RsaPublicKey, 
		g_RsaPublicKeySize,
		(const char *)g_RsaPrivateKey,
		g_RsaPrivateKeySize);
#elif defined (PUBLIC_KEY_TEST_DSS_KEY)
	result = ptssh.authByPublicKey( 
		(const char *)g_DssPublicKey, 
		g_DssPublicKeyLen,
		(const char *)g_DssPrivateKey,
		g_DssPrivateKeyLen);
#else
	//Enter int your password here!
	result = ptssh.authByPassword(g_pPassword);
#endif

	if ( result != PTSSH_SUCCESS)
		PTLOG((LL_error, "Failed to authenticate by public key\n"));
	else
	{
		printf("Authentication succeeded!\n");

#ifdef REMOTE_PORT_FORWARD
		result = ptssh.requestRemotePortFowarding(
			g_callbackFunc,
			NULL,
			g_pRemotePortForwardAddr,
			g_remotePortForwardPort,
			2);
		if ( result == PTSSH_SUCCESS)
		{
			printf("Remote port forwarding listening on %s:%d\n", g_pRemotePortForwardAddr, g_remotePortForwardPort);

			while (1)
				Sleep(1);

			result = ptssh.cancelRemotePortFowarding(g_pRemotePortForwardAddr, g_remotePortForwardPort);
			if ( result == PTSSH_SUCCESS)
				printf("REmote port forwarding canceled\n");
		}
#endif

#ifdef X11_TEST
		uint32 
			cNum = PTSSH_BAD_CHANNEL_NUMBER,
			result = ptssh.createChannel_session(cNum);
		if ( result == PTSSH_SUCCESS)
		{
			////Now to get an X11 request to come across, we need to fire off a command
			////Xming listens on port 6000
			result = ptssh.channelRequest_x11Forwarding(cNum);
			if ( result == PTSSH_SUCCESS)
			{
				Data *pData = NULL;
				result = ptssh.channelRequest_pty(cNum, "VT100");
				if ( result == PTSSH_SUCCESS)
				{
					result = ptssh.channelRequest_shell(cNum);
					if ( result == PTSSH_SUCCESS)
					{
						//Sleep(1000);
						//if ( ptssh.channelRead(cNumCmd, &pData) == PTSSH_SUCCESS)
						//{
						//	PTLOG(("Read data: %s!\n", pData->data()));
						//	delete pData;
						//}

						char cmd[] = "kwrite\r";
						ptssh.channelWrite(cNum, cmd, (uint32)strlen(cmd));

						while (g_bKeepRunning)
						{
							if ( ptssh.channelRead(cNum, &pData, true, 1000) == PTSSH_SUCCESS)
							{
								char *pPretty = new char[pData->dataLen() + 1];
								memcpy( pPretty, pData->getDataPtr(), pData->dataLen());
								pPretty[pData->dataLen()] = 0x0; //NULL terminate
								printf("Read data (%d): %s!\n", pData->dataLen(), pPretty);
								delete []pPretty;
								delete pData;
							}

							//if ( ptssh.channelRead(cNum, &pData, true, 1000) == PTSSH_SUCCESS)
							//{
							//	printf("X11 data received!\n");
							//}

							//if ( ptssh.channelRead(cNum, &pData, true, 1000, true) == PTSSH_SUCCESS)
							//{
							//	printf("X11 data received!\n");
							//}
						}
					}
				}
			}
		}
#endif
//
//#ifdef PTSSH_SFTP
//		PTSftp *pSftp = NULL;
//		int32
//			result = ptssh.initSFTP( &pSftp);
//		if ( result == PTSSH_SUCCESS)
//		{
//			printf("Requesting sftp subsystem success!\n");
//
//		}
//#endif

#ifdef TERMINAL_TEST
		uint32 channelNum = -1;
		int32 result = ptssh.createChannel_session(channelNum);
		if ( result >= 0)
		{
			if (ptssh.channelRequest_pty( channelNum, "vt100") >= 0)
			{
				if (ptssh.channelRequest_shell( channelNum) >= 0)
				{
					Data *pData = NULL;
					if ( ptssh.channelRead(channelNum, &pData, true) == PTSSH_SUCCESS)
					{
						char *pC = (char*) pData->data() + 9;
						printf("Got data: %s!\n", pC);
						delete pData;
						pData = NULL;
					}

					if ( ptssh.channelRead(channelNum, &pData, true) == PTSSH_SUCCESS)
					{
						char *pC = (char*) pData->data() + 9;
						printf("Got data: %s!\n", pC);
						delete pData;
						pData = NULL;
					}

					if ( ptssh.channelWrite(channelNum, "ls -lha\r", strlen("ls -lha\r")))
					{
						Sleep( 1000);
						while ( ptssh.channelRead(channelNum, &pData, false) == PTSSH_SUCCESS)
						{
							char *pC = (char*) pData->data() + 9;
							printf("Got data: %s!\n", pC);
							delete pData;
							pData = NULL;
						}
					}

				}
			}
		}
#endif /* TERMINAL_TEST */

#ifdef EXEC_TEST
		uint32 channelNum2 = -1;
		result = ptssh.createChannel_session(channelNum2);
		if ( result  == PTSSH_SUCCESS)
		{
			printf("Opened channel %d\n", channelNum2);
			result = ptssh.channelRequest_exec( channelNum2, "/usr/bin/eject");
		}

		uint32 channelNum3 = -1;
		result = ptssh.createChannel_session(channelNum3);

		if ( result  == PTSSH_SUCCESS)
		{
			printf("Opened channel %d\n", channelNum3);
			result = ptssh.channelRequest_exec( channelNum3, "/usr/bin/eject -t");
		}
#endif /* EXEC_TEST */




#ifdef SCP_SEND_TEST

		pFileHandle = fopen(pLocalFile, "rb");
		if ( ! pFileHandle) {
			PTLOG((LL_error, "Can't local file %s\n", pLocalFile));
			ptssh.disconnect();
			return -1;
		}

		//Get the file statistics
		stat(pLocalFile, &fileInfo);

		uint32
			cNum3 = -1,
			optimalSize = -1,
			totalBytesQueued = 0;
		result = ptssh.scpSendInit(cNum3, optimalSize, pRemoteFileToGet, fileInfo.st_size);
		if ( result == PTSSH_SUCCESS)
		{
			uint32 fileSize = (uint32)fileInfo.st_size;
			char *pBuf = new char[optimalSize];
			if ( pBuf)
			{
				bool bKeepGoing = true;
				int32 bytesRead = 1;
				//Read the file and send the data over the channel

				printf("Queueing %uMB for sending\n", (fileSize>>20) );
//				timer.start();
				//time_t
				//	start = time(NULL),
				//	stop;
				clock_t
					start = clock(),
					stop;
				while ( bytesRead > 0)
				{
					bytesRead = fread(pBuf, 1, optimalSize, pFileHandle);
					if (bytesRead > 0) {
						int32 result = ptssh.channelWrite(cNum3, pBuf, bytesRead);
						if ( result != PTSSH_SUCCESS)
						{
							printf("Failed to write channel data. Error %d\n", result);
							break;
						}
						else
						{
							totalBytesQueued += bytesRead;
							//if ( totalBytesQueued > 0x1000000)
							//	Sleep(1);

							//PTLOG(("[PTssh] Queued %dKB out of %uKB (%4.2f%%))\n",
							//	(totalBytesQueued>>10), (fileSize>>10), 
							//	(((double)totalBytesQueued) / ((double)fileSize) )* 100);
						}
					}
				}
				printf("Done queueing %uMB for sending\n", (fileSize>> 20) );

				delete pBuf;
				pBuf = NULL;

				result = ptssh.scpSendFinish(cNum3);
				//timer.stop();
				//timer.print();
				//stop = time(NULL);
				stop = clock();
				if ( result == PTSSH_SUCCESS)
				{
					//double 
					//	elapsedTimeInMsec = timer.elapsedTimeInMsec(),
					//	elapsedTimeInSec = elapsedTimeInMsec / 100 / 2,
					//	KbytesPerSec = (fileInfo.st_size/1024) / (elapsedTimeInSec),
					//	MbytesPerSec = ((((double)fileInfo.st_size)/1024)/1024) / (elapsedTimeInSec);
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
					printf("SCP transfer success!\n");
				}
				else
					printf("SCP transfer failed\n");
			}
			fclose(pFileHandle);
		}
#endif /* SCP_SEND_TEST */

#ifdef SCP_RECEIVE_TEST

		pRecvFileHandle = fopen( pLocalFileName, "wb");
		if ( pRecvFileHandle)
		{
			uint32 cNumReceive;
			struct stat fileInfo;
			memset( &fileInfo, 0x0, sizeof(struct stat));
			uint64
				recvdBytes = 0;
			clock_t
				start = clock(),
				stop;
			if ( ptssh.scpReceiveInit(cNumReceive, fileInfo, pRemoteFileRecv) == PTSSH_SUCCESS)
			{
				while (recvdBytes < fileInfo.st_size)
				{
					Data *pPD = NULL;
					if ( ptssh.channelRead(cNumReceive, &pPD, true) == PTSSH_SUCCESS)
					{
						if ( pPD)
						{
							uint32
								dataSize = pPD->dataLen(),
								writeSize = dataSize;
							uint8
								*pData = pPD->data();

							/* Seems scp likes to give us a Null terminator appended to the end of 
							 * the stream right after the last byte in the file. So if we have
							 * more bytes than we are expecting, don't write the additional byte. */
							if ( (fileInfo.st_size - recvdBytes) < dataSize)
								writeSize = dataSize - 1;

							uint32 len = fwrite( pData, writeSize, 1, pRecvFileHandle);
							if ( len != 1)
							{
								printf("Write file error!\n");
								break;
							}
							else
							{
								recvdBytes += writeSize;
								
								printf("[main] Got %d (%d/%d%d) bytes\n", 
									writeSize, 
									recvdBytes, 
									fileInfo.st_size, 
									fileInfo.st_size);
							}

							delete pPD;
							pPD = NULL;
						}
					}
				}

				if ( ptssh.scpReceiveFinish(cNumReceive) == PTSSH_SUCCESS)
				{
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
					printf("SCP receive successful!\n");
				}
				else
				{
					printf("SCP receive failed\n");
				}
			}
			else
			{
				printf("SCP receive failed\n");
			}

			fclose(pRecvFileHandle);
		}
		else
		{
			printf("Couldn't create local file %s\n", pLocalFileName);
		}
#endif /* SCP_RECEIVE_TEST */
	}

	//Close down our connection
	ptssh.disconnect();
}

#ifdef X11_TEST
void shutdown(int sig)
{
	printf("Sig %d. Shutting down...\n", sig);
	g_bKeepRunning = false;
}
#endif