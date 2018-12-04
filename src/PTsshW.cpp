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



#include "PTsshW.h"
#include "PTssh.h"
#include "Data.h"
#include "SftpAttrs.h"

#ifdef WIN32
#   include <windows.h>
#endif

#include <string.h>

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API PTssh*
ptssh_create()
{
	return new PTssh();
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API void 
ptssh_destroy(PTssh **ppSSHObj)
{
	if ( *ppSSHObj)
	{
		delete *ppSSHObj;
		*ppSSHObj = NULL;
	}
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_init(PTssh *pSSHObj, const char *username, const char *remoteHostAddress, uint16 remotePort)
{
	if (pSSHObj)
		return pSSHObj->init(
			username,
			remoteHostAddress,
			remotePort);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_getVersionInfo(PTssh *pSSHObj, char **ppVerStr)
{
	if (pSSHObj)
		return pSSHObj->getVersionInfo(ppVerStr);
	else
		return NULL;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_setLogLevel(PTssh *pSSHObj, PTSSH_LogLevel level)
{
	if (pSSHObj)
		return pSSHObj->setLogLevel(level);
	else
		return NULL;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API const char * 
ptssh_getUsername(PTssh *pSSHObj)
{
	if (pSSHObj)
		return pSSHObj->getUsername();
	else
		return NULL;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API const char * 
ptssh_getRemoteHostAddress(PTssh *pSSHObj)
{
	if (pSSHObj)
		return pSSHObj->getRemoteHostAddress();
	else
		return NULL;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API uint16 
ptssh_getRemoteHostPort(PTssh *pSSHObj)
{
	if (pSSHObj)
		return pSSHObj->getRemoteHostPort();
	else
		return NULL;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_connect(PTssh *pSSHObj)
{
	if (pSSHObj)
		return pSSHObj->connectUp();
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_disconnect(PTssh *pSSHObj)
{
	if (pSSHObj)
		return pSSHObj->disconnect();
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_isAuthSupported(PTssh *pSSHObj, PTsshAuthMethod authType,	bool &bResult)
{
	if (pSSHObj)
		return pSSHObj->isAuthSupported(authType, bResult);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_authByPassword(PTssh *pSSHObj, const char * password, const char *oldPassword)
{
	if (pSSHObj)
		return pSSHObj->authByPassword(password, oldPassword);
	else
		return PTSSH_ERR_InvalidObject;
}

 //////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_createChannel_session(PTssh *pSSHObj, uint32 &cNum) 
{
	if (pSSHObj)
		return pSSHObj->createChannel_session(cNum);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_requestRemotePortFowarding(
	PTssh *pSSHObj,
	void (*pCallbackFunc)(struct PTsshCallBackData*),
	void *pCallbackData,
	const char *IPAddr,
	uint16 port,
	uint32 maxConnections)
{
	if (pSSHObj)
		return pSSHObj->requestRemotePortFowarding(
			pCallbackFunc,
			pCallbackData,
			IPAddr,
			port,
			maxConnections);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_cancelRemotePortFowarding(
		PTssh *pSSHObj,
		const char *IPAddr,
		uint16 port)
{
	if (pSSHObj)
		return pSSHObj->cancelRemotePortFowarding(IPAddr, port);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_createChannel_directTCPIP(
	PTssh *pSSHObj,
	uint32 &cNum,
	const char *pDestAddress,
	uint16 destPort,
	const char *pSourceIPAddress,
	uint16 sourcePort)
{
	if (pSSHObj)
		return pSSHObj->createChannel_directTCPIP(
			cNum,
			pDestAddress,
			destPort,
			pSourceIPAddress,
			sourcePort);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_createChannel_AutomaticDirectTCPIP(
	PTssh *pSSHObj,
	int localSocket,
	int totalConnections,
	int32 (*callbackFuncPtr)(void *ptrStorage),
	const char *destAddress,
	uint16 destPort,
	const char *sourceIPAddress,
	uint16 sourcePort)
{
	if (pSSHObj)
		return pSSHObj->createChannel_AutomaticDirectTCPIP(
			localSocket,
			totalConnections,
			callbackFuncPtr,
			destAddress,
			destPort,
			sourceIPAddress,
			sourcePort);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_closeAutomaticDirectTCPIP(PTssh *pSSHObj, int localSocket)
{
	if (pSSHObj)
		return pSSHObj->closeAutomaticDirectTCPIP(localSocket);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_closeChannel(PTssh *pSSHObj,	uint32 channelNumber)
{
	if (pSSHObj)
		return pSSHObj->closeChannel(channelNumber);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_channelRequest_pty(
	PTssh *pSSHObj,
	uint32 channelNumber,
	const char * terminalType,
	uint32 termCharWidth,
	uint32 termCharHeight,
	uint32 termPixWidth,
	uint32 termPixHeight,
	const char * termModes)
{
	if (pSSHObj)
		return pSSHObj->channelRequest_pty(
			channelNumber,
			terminalType,
			termCharWidth,
			termCharHeight,
			termPixWidth,
			termPixHeight,
			termModes);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_channelRequest_shell(PTssh *pSSHObj, uint32 channelNumber)
{
	if (pSSHObj)
		return pSSHObj->channelRequest_shell(channelNumber);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_channelRequest_x11Forwarding(
	PTssh *pSSHObj,
	uint32 channelNumber,
	uint32 screenNumber,
	bool bSingleConnectionOnly)
{
	if (pSSHObj)
		return pSSHObj->channelRequest_x11Forwarding(
			channelNumber,
			screenNumber,
			bSingleConnectionOnly);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_channelRequest_env(
	PTssh *pSSHObj,
	uint32 channelNumber,
	const char *variableName,
	const char *variableValue)
{
	if (pSSHObj)
		return pSSHObj->channelRequest_env(
			channelNumber,
			variableName,
			variableValue);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_channelRequest_exec(
	PTssh *pSSHObj,
	uint32 channelNumber,
	const char * commandToExecute)
{
	if (pSSHObj)
		return pSSHObj->channelRequest_exec(channelNumber, commandToExecute);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_channelRequest_subsystem(
	PTssh *pSSHObj,
	uint32 channelNumber,
	const char *pSubsystemName)
{
	if (pSSHObj)
		return pSSHObj->channelRequest_subsystem(channelNumber, pSubsystemName);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_channelRequest_windowChange(
	PTssh *pSSHObj,
	uint32 channelNumber,
	uint32 termCharWidth,
	uint32 termCharHeight,
	uint32 termPixWidth,
	uint32 termPixHeight)
{
	if (pSSHObj)
		return pSSHObj->channelRequest_windowChange(
			channelNumber,
			termCharWidth,
			termCharHeight,
			termPixWidth,
			termPixHeight);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_channelRequest_sendSignal(
	PTssh *pSSHObj,
	const uint32 &channelNumber,
	const PTsshChannelSignalType &eSignal)
{
	if (pSSHObj)
		return pSSHObj->channelRequest_sendSignal(channelNumber, eSignal);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_channelRequest_exitStatus(
	PTssh *pSSHObj,
	uint32 channelNumber,
	uint32 &exitStatus)
{
	if (pSSHObj)
		return pSSHObj->channelRequest_exitStatus(channelNumber, exitStatus);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_channelRequest_exitSignal(
	PTssh *pSSHObj,
	uint32 channelNumber,
	uint32 &exitSignal)
{
	if (pSSHObj)
		return pSSHObj->channelRequest_exitSignal(channelNumber, exitSignal);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_channelRead(
	PTssh *pSSHObj,
	uint32 channelNumber,
	char **ppData,
	uint32 &dataLen,
	bool bIsBlockingRead,
	uint32 microsecTimeout,
	bool bExtendedData)
{
	if (pSSHObj)
	{
		*ppData = NULL;
		dataLen = 0;
		Data *pPTsshData = NULL;
		int32 result = pSSHObj->channelRead(
			channelNumber,
			&pPTsshData,
			bIsBlockingRead,
			microsecTimeout,
			bExtendedData);
		if ( result == PTSSH_SUCCESS && pPTsshData != NULL)
		{
			//Copy the data out and put it in char* form
			*ppData = new char[pPTsshData->dataLen()];
			if ( *ppData)
			{
				dataLen = pPTsshData->dataLen();
				memcpy( *ppData, pPTsshData->getDataPtr(), dataLen);
			}
			else
				result = PTSSH_ERR_CouldNotAllocateMemory;

			delete pPTsshData;
		}

		return result;
	}
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_channelWrite(
	PTssh *pSSHObj,
	uint32 channelNumber,
	const char *pBuffer,
	uint32 bufferSize)
{
	if (pSSHObj)
		return pSSHObj->channelWrite(
			channelNumber,
			pBuffer,
			bufferSize);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_getOptimalDataSize( PTssh *pSSHObj, uint32 channelNumber, uint32 &byteLength)
{
	if (pSSHObj)
		return pSSHObj->getOptimalDataSize(channelNumber, byteLength);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_channelGetEOF(
	PTssh *pSSHObj,
	uint32 channelNumber,
	bool &bResult)
{
	if (pSSHObj)
		return pSSHObj->channelGetEOF(channelNumber, bResult);
	else
		return PTSSH_ERR_InvalidObject;
}

#ifdef PTSSH_SCP
///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_scpSendInit(
	PTssh *pSSHObj,
	uint32 &cNum,
	uint32 &optimalSize,
	const char *pRemoteFilePath,
	uint64 fileSizeInBytes,
	uint32 fileCreateFlags)
{
	if (pSSHObj)
		return pSSHObj->scpSendInit(
			cNum,
			optimalSize,
			pRemoteFilePath,
			fileSizeInBytes,
			fileCreateFlags);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_scpSendFinish(PTssh *pSSHObj, uint32 channelNumber) 
{
	if (pSSHObj)
		return pSSHObj->scpSendFinish(channelNumber);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_scpReceiveInit(
	PTssh *pSSHObj,
	uint32 &cNum,
	struct stat &fileInfo,
	const char *pRemoteFilePath)
{
	if (pSSHObj)
		return pSSHObj->scpReceiveInit(cNum, fileInfo, pRemoteFilePath);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_scpReceiveFinish(PTssh *pSSHObj, uint32 cNum)
{
	if (pSSHObj)
		return pSSHObj->scpReceiveFinish( cNum);
	else
		return PTSSH_ERR_InvalidObject;
}
#endif /* PTSSH_SCP */

#ifdef PTSSH_SFTP
///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32
ptssh_initSftp(PTssh *pSSHObj)
{
	if (pSSHObj)
		return pSSHObj->initSFTP();
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API PTSftp * 
ptssh_getSftpObj(PTssh *pSSHObj)
{
	if (pSSHObj)
		return pSSHObj->getSftpObj();
	else
		return NULL;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_shutdownSftp(PTssh *pSSHObj)
{
	if (pSSHObj)
		return pSSHObj->shutdownSftp();
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API uint32 
ptssh_getSftpVersion(PTSftp * pSftp)
{
	if (pSftp)
		return pSftp->getSftpVersion();
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_openFile(
		PTSftp * pSftp,
		SftpFileHandle **ppSftpFileHandle,
		const char *fileName,
		uint32 pflags)
{
	if (pSftp)
		return pSftp->openFile(
			ppSftpFileHandle,
			fileName,
			pflags);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_closeFile(
		PTSftp * pSftp,
		SftpFileHandle **ppSftpFileHandle)
{
	if (pSftp)
		return pSftp->closeFile(ppSftpFileHandle);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_deleteFile(
		PTSftp * pSftp,
		const char *pFileName)
{
	if (pSftp)
		return pSftp->deleteFile(pFileName);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_renameFileOrDir(
		PTSftp * pSftp,
		const char *pOldName,
		const char *pNewName)
{
	if (pSftp)
		return pSftp->renameFileOrDir(pOldName, pNewName);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_makeDir(
		PTSftp * pSftp,
		const char *pNewDir,
		SFTP_W_ATTR *pAttr)
{
	if (pSftp)
	{
		SftpAttrs attrs;
		attrs.gid(pAttr->gid);
		attrs.uid(pAttr->uid);
		attrs.permissions(pAttr->permissions);

		return pSftp->makeDir(pNewDir, &attrs);
	}
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_deleteDir(
		PTSftp * pSftp,
		const char *pPath)
{
	if (pSftp)
		return pSftp->deleteDir(pPath);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_openDir(
		PTSftp * pSftp,
		SftpDirHandle **ppSftpDirHandle,
		const char *pPath)
{
	if (pSftp)
		return pSftp->openDir(ppSftpDirHandle, pPath);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_closeDir(
		PTSftp * pSftp,
		SftpDirHandle **ppSftpDirHandle)
{
	if (pSftp)
		return pSftp->closeDir(ppSftpDirHandle);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_getFileAttrUsingHandle(
		PTSftp * pSftp,
		const char *pPath,
		bool bFollowSymLinks,
		SFTP_W_ATTR *pAttr)
{
	int32 result;
	if (pSftp)
	{
		SftpAttrs attrs;

		if ( ! pAttr)
			return PTSSH_ERR_NullPointerGiven;

		result = pSftp->getFileAttributes(pPath, bFollowSymLinks, &attrs);
		if ( result == PTSSH_SUCCESS)
		{
			pAttr->gid = attrs.gid();
			pAttr->uid = attrs.uid();
			pAttr->size = attrs.fileSize();
			pAttr->permissions = attrs.permissions();
		}
	}
	else
		result = PTSSH_ERR_InvalidObject;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_createSymLink(
		PTSftp * pSftp,
		const char *pLinkPath,
		const char *pTargetPath)
{
	if (pSftp)
		return pSftp->createSymLink(pLinkPath, pTargetPath);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_readFile(
		SftpFileHandle * pSftpFileHandle,
		uint8 *pBuf,
		uint32 bufLen,
		uint64 offset,
		uint32 &bytesRead)
{
	if (pSftpFileHandle)
		return pSftpFileHandle->read(pBuf, bufLen, offset, bytesRead);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_writeFile(
		SftpFileHandle * pSftpFileHandle,
		const uint8 *pBuf,
		uint32 bufLen)
{
	if (pSftpFileHandle)
		return pSftpFileHandle->write(pBuf, bufLen);
	else
		return PTSSH_ERR_InvalidObject;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_getFileAttributes(
		SftpFileHandle * pSftpFileHandle,
		SFTP_W_ATTR *pAttrs)
{
	int32 result;
	if (pSftpFileHandle)
	{
		SftpAttrs attrs;

		if ( ! pAttrs)
			return PTSSH_ERR_NullPointerGiven;

		result = pSftpFileHandle->getFileAttributes( &attrs);
		if ( result == PTSSH_SUCCESS)
		{
			pAttrs->gid = attrs.gid();
			pAttrs->uid = attrs.uid();
			pAttrs->size = attrs.fileSize();
			pAttrs->permissions = attrs.permissions();
		}
	}
	else
		result = PTSSH_ERR_InvalidObject;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
PTsshWRAPPER_API int32 
ptssh_readDir(
		SftpDirHandle * pSftpDirHandle,
		DirectoryItem **ppDI, 
		uint32 &itemCount)
{
	if (pSftpDirHandle)
		return pSftpDirHandle->readDir(ppDI, itemCount);
	else
		return PTSSH_ERR_InvalidObject;
}
#endif /* PTSSH_SFTP */