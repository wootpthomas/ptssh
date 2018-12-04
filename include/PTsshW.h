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


#ifndef _C_DLL_PTSSH_WRAPPER
#define _C_DLL_PTSSH_WRAPPER

#ifdef WIN32
#  ifdef PTsshWRAPPER_EXPORTS
#    define PTsshWRAPPER_API __declspec(dllexport)
#  else
#    define PTsshWRAPPER_API __declspec(dllimport)
#  endif
#else
#  define PTsshWRAPPER_API
#endif


/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"  //Used for types

#ifdef PTSSH_SFTP
#  include "PTSftp.h"
#  include "SftpFileHandle.h"
#  include "SftpDirHandle.h"
#endif

/*************************
 * Forward Declarations
 ************************/


/*************************
 * Data Type Definitions
 ************************/
struct SftpWrapperAttributes {   //The current struct is SFTP ver3 based
	uint32
		uid,
		gid,
		permissions;
	uint64
		size;
};


/*************************
 * Alias
 ************************/
typedef struct SftpWrapperAttributes SFTP_W_ATTR;

#ifdef __cplusplus
   extern "C" {
#endif

/* The purpose of this wrapper is to provide a C interface to our C++ PTssh class. This
 * will allow us to create a library (DLL/SO) that can then be more widely used by other
 * languages that can not directly use the PTssh C++ class. This should enable other people
 * to more easily create wrappers for Java, .Net, Perl, PHP, etc...
 */
#if defined(_WIN32) //&& defined(MSVC_VER)
//Hide the MSVC warning: warning C4099: 'PTssh' : type name first seen using 'class' now seen using 'struct'
#  pragma warning (disable:4099)
#endif
typedef struct PTssh PTssh;  /* Makes the PTssh C++ class opaque to the wrapper. This is part
							 of the magick that wraps up our C++ class */
#ifdef PTSSH_SFTP
	typedef struct PTSftp PTSftp;
	typedef struct SftpFileHandle SftpFileHandle;
	typedef struct SftpDirHandle  SftpDirHandle;
#endif

PTsshWRAPPER_API PTssh * ptssh_create();

PTsshWRAPPER_API void ptssh_destroy(
		PTssh **ppSSHObj);

PTsshWRAPPER_API int32 ptssh_init(
		PTssh *pSSHObj,
		const char *username,
		const char *remoteHostAddress,
		uint16 remotePort = 22);

PTsshWRAPPER_API int32 ptssh_getVersionInfo(
		PTssh *pSSHObj,
	    char **ppVerStr);

PTsshWRAPPER_API int32 ptssh_setLogLevel(
		PTssh *pSSHObj,
	    PTSSH_LogLevel level);

PTsshWRAPPER_API const char * ptssh_getUsername(
		PTssh *pSSHObj);

PTsshWRAPPER_API const char * ptssh_getRemoteHostAddress(
		PTssh *pSSHObj);

PTsshWRAPPER_API uint16 ptssh_getRemoteHostPort(
		PTssh *pSSHObj);

//PTsshWRAPPER_API bool ptssh_setCallbackFunction(
//		PTssh *pSSHObj,
//		CallbackType type,
//		void * pCallbackFunc);

PTsshWRAPPER_API int32 ptssh_connect(
		PTssh *pSSHObj);

PTsshWRAPPER_API int32 ptssh_disconnect(
		PTssh *pSSHObj);

PTsshWRAPPER_API int32 ptssh_getServerHostKey(
	PTssh *pSSHObj,
	uint8** ppBuf,
	uint32 &bufLen,
	bool bAsMD5_hash);

PTsshWRAPPER_API int32 ptssh_isAuthSupported(
		PTssh *pSSHObj,
		PTsshAuthMethod authType,
		bool &bResult);

PTsshWRAPPER_API int32 ptssh_isPublicKeyAcceptable(
		PTssh *pSSHObj,
		bool &bResult,
		const char *pPublicKeyBlob64, 
		uint32 pPublicKeyBlob64Len,
		const char *pPrivateKeyBlob64,
		uint32 pPrivateKeyBlob64Len,
		const char *passphrase);

PTsshWRAPPER_API int32 ptssh_authByPublicKey(
		PTssh *pSSHObj,
		const char *pPublicKeyBlob64, 
		uint32 pPublicKeyBlob64Len,
		const char *pPrivateKeyBlob64,
		uint32 pPrivateKeyBlob64Len, 
		const char *passphrase);

PTsshWRAPPER_API int32 ptssh_authByPassword(
		PTssh *pSSHObj,
		const char * password,
		const char *oldPassword = 0);

//PTsshWRAPPER_API int32 authByHost(PTssh *pSSHObj);

PTsshWRAPPER_API int32 ptssh_createChannel_session(
		PTssh *pSSHObj,
		uint32 &channelNumber);

PTsshWRAPPER_API int32 ptssh_requestRemotePortFowarding(
		PTssh *pSSHObj,
		void (*pCallbackFunc)(struct PTsshCallBackData*),
		void *pCallbackData,
		const char *IPAddr,
		uint16 port,
		uint32 maxConnections);

PTsshWRAPPER_API int32 ptssh_cancelRemotePortFowarding(
		PTssh *pSSHObj,
		const char *IPAddr,
		uint16 port);

PTsshWRAPPER_API int32 ptssh_createChannel_directTCPIP(
		PTssh *pSSHObj,
		uint32 &cNum,
		const char *destAddress,
		uint16 destPort,
		const char *sourceIPAddress = "127.0.0.1",
		uint16 sourcePort = 22);

PTsshWRAPPER_API int32 ptssh_createChannel_AutomaticDirectTCPIP(
		PTssh *pSSHObj,
		int localSocket,
		int totalConnections,
		int32 (*callbackFuncPtr)(void *ptrStorage),
		const char *destAddress,
		uint16 destPort,
		const char *sourceIPAddress,
		uint16 sourcePort);

PTsshWRAPPER_API int32 ptssh_closeAutomaticDirectTCPIP(
		PTssh *pSSHObj,
		int localSocket);

PTsshWRAPPER_API int32 ptssh_closeChannel(
		PTssh *pSSHObj,
		uint32 channelNumber);

	/**********************************
	 * Channel Requests
	 **********************************/
PTsshWRAPPER_API int32 ptssh_channelRequest_pty(
		PTssh *pSSHObj,
		uint32 channelNumber,
		const char * terminalType,
		uint32 termCharWidth = PTSSH_TERM_WIDTH,
		uint32 termCharHeight = PTSSH_TERM_WIDTH,
		uint32 termPixWidth = 0,
		uint32 termPixHeight = 0,
		const char * termModes = "");

PTsshWRAPPER_API int32 ptssh_channelRequest_shell(
		PTssh *pSSHObj,
		uint32 channelNumber);

PTsshWRAPPER_API int32 ptssh_channelRequest_x11Forwarding(
	PTssh *pSSHObj,
	uint32 channelNumber,
	uint32 screenNumber,
	bool bSingleConnectionOnly);

PTsshWRAPPER_API int32 ptssh_channelRequest_env(
		PTssh *pSSHObj,
		uint32 channelNumber,
		const char *variableName,
		const char *variableValue);

PTsshWRAPPER_API int32 ptssh_channelRequest_exec(
		PTssh *pSSHObj,
		uint32 channelNumber,
		const char * commandToExecute);

PTsshWRAPPER_API int32 ptssh_channelRequest_subsystem(
		PTssh *pSSHObj,
		uint32 channelNumber,
		const char *pSubsystemName);

PTsshWRAPPER_API int32 ptssh_channelRequest_windowChange(
		PTssh *pSSHObj,
		uint32 channelNumber,
		uint32 termCharWidth = PTSSH_TERM_WIDTH,
		uint32 termCharHeight = PTSSH_TERM_WIDTH,
		uint32 termPixWidth = 0,
		uint32 termPixHeight = 0);

PTsshWRAPPER_API int32 ptssh_channelRequest_sendSignal(
		PTssh *pSSHObj,
		const uint32 &nChannelnumber,
		const PTsshChannelSignalType &eSignal);

PTsshWRAPPER_API int32 ptssh_channelRequest_exitStatus(
		PTssh *pSSHObj,
		uint32 channelNumber,
		uint32 &exitStatus);

PTsshWRAPPER_API int32 ptssh_channelRequest_exitSignal(
		PTssh *pSSHObj,
		uint32 channelNumber,
		uint32 &exitSignal);

PTsshWRAPPER_API int32 ptssh_channelRead(
		PTssh *pSSHObj,
		uint32 channelNumber,
		char **ppData,
		uint32 &dataLen,
		bool bIsBlockingRead = true,
		uint32 microsecTimeout = 0,
		bool bExtendedData = false);

PTsshWRAPPER_API int32 ptssh_channelWrite(
		PTssh *pSSHObj,
		uint32 channelNumber,
		const char *pBuffer,
		uint32 bufferSize);

PTsshWRAPPER_API int32 ptssh_getOptimalDataSize(
		PTssh *pSSHObj,
		uint32 channelNumber,
		uint32 &byteLength);

PTsshWRAPPER_API int32 ptssh_channelGetEOF(
		PTssh *pSSHObj,
		uint32 channelNumber,
		bool &bResult);

	/*****************
	* Secure Copy related
	*****************/
#ifdef PTSSH_SCP
PTsshWRAPPER_API int32 ptssh_scpSendInit(
		PTssh *pSSHObj,
		uint32 &cNum,
		uint32 &optimalSize,
		const char *pRemoteFilePath,
		uint64 fileSizeInBytes,
		uint32 fileCreateFlags = 0x1FF);

PTsshWRAPPER_API int32 ptssh_scpSendFinish(
		PTssh *pSSHObj,
		uint32 channelNumber);

PTsshWRAPPER_API int32 ptssh_scpReceiveInit(
		PTssh *pSSHObj,
		uint32 &cNum,
		struct stat &fileInfo,
		const char *pRemoteFilePath);

PTsshWRAPPER_API int32 ptssh_scpReceiveFinish(
		PTssh *pSSHObj,
		uint32 channelNumber);
#endif /* PTSSH_SCP */

	/**********************************
	 * SFTP API
	 **********************************/
#ifdef PTSSH_SFTP
PTsshWRAPPER_API int32 ptssh_initSftp(
		PTssh *pSSHObj);

PTsshWRAPPER_API PTSftp * ptssh_getSftpObj(
		PTssh *pSSHObj);

PTsshWRAPPER_API int32 ptssh_shutdownSftp(
		PTssh *pSSHObj);

PTsshWRAPPER_API uint32 ptssh_getSftpVersion(
		PTSftp * pSftp);

PTsshWRAPPER_API int32 ptssh_openFile(
		PTSftp * pSftp,
		SftpFileHandle **ppSftpFileHandle,
		const char *fileName,
		uint32 pflags);

PTsshWRAPPER_API int32 ptssh_closeFile(
		PTSftp * pSftp,
		SftpFileHandle **ppSftpFileHandle);

PTsshWRAPPER_API int32 ptssh_deleteFile(
		PTSftp * pSftp,
		const char *pFileName);

PTsshWRAPPER_API int32 ptssh_renameFileOrDir(
		PTSftp * pSftp,
		const char *pOldName,
		const char *pNewName);

PTsshWRAPPER_API int32 ptssh_makeDir(
		PTSftp * pSftp,
		const char *pNewDir,
		SFTP_W_ATTR *pAttr);

PTsshWRAPPER_API int32 ptssh_deleteDir(
		PTSftp * pSftp,
		const char *pPath);

PTsshWRAPPER_API int32 ptssh_openDir(
		PTSftp * pSftp,
		SftpDirHandle **ppSftpDirHandle,
		const char *pPath);

PTsshWRAPPER_API int32 ptssh_closeDir(
		PTSftp * pSftp,
		SftpDirHandle **ppSftpDirHandle);

PTsshWRAPPER_API int32 ptssh_getFileAttrUsingHandle(
		PTSftp * pSftp,
		const char *pPath,
		bool bFollowSymLinks,
		SFTP_W_ATTR *pAttr);

PTsshWRAPPER_API int32 ptssh_createSymLink(
		PTSftp * pSftp,
		const char *pLinkPath,
		const char *pTargetPath);

	/**********************************
	 * SFTP File handle API
	 **********************************/
PTsshWRAPPER_API int32 ptssh_readFile(
		SftpFileHandle * pSftp,
		uint8 *pBuf,
		uint32 bufLen,
		uint64 offset,
		uint32 &bytesRead);

PTsshWRAPPER_API int32 ptssh_writeFile(
		SftpFileHandle * pSftp,
		const uint8 *pBuf,
		uint32 bufLen);

	/**
	* This will get the file attributes from an existing Sftp file handle
	*/
PTsshWRAPPER_API int32 ptssh_getFileAttributes(
		SftpFileHandle * pSftp,
		SFTP_W_ATTR *pAttr);

	/**********************************
	 * SFTP Directory handle API
	 **********************************/
PTsshWRAPPER_API int32 ptssh_readDir(
		SftpDirHandle *pSftp,
		DirectoryItem **ppDI, 
		uint32 &itemCount);
#endif /* PTSSH_SFTP */
#ifdef __cplusplus
   }
#endif

#endif /* _C_DLL_PTSSH_WRAPPER */
