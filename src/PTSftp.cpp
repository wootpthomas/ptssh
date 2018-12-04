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

/*************************
 * Includes
 ************************/

#include "PTSftp.h"

#ifdef PTSSH_SFTP

#include "PTssh.h"
#include "PTsshLog.h"
#include "Transport.h"
#include "ChannelManager.h"
#include "Data.h"
#include "SftpBinaryPacket.h"
#include "SSH2Types.h"
#include "PTsshLog.h"
#include "SftpAttrs.h"
#include "SftpFileHandle.h"
#include "SftpDirHandle.h"
#include "Utility.h"
#include "SftpRequestMgr.h"

#include <string.h>

#if defined(WIN32)
#  define snprintf _snprintf
#  if defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
#    define _CRTDBG_MAP_ALLOC
#    include <stdlib.h>
#    include <crtdbg.h>
#    define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#    define new DEBUG_NEW
#  endif
#endif






///////////////////////////////////////////////////////////////////////////////
PTSftp::PTSftp(PTssh *pPTsshObj, ChannelManager *pChannelMgrObj, uint32 channelNum):
m_pPTssh( pPTsshObj),
m_pChannelMgr( pChannelMgrObj),
m_CNum( channelNum),
m_requestedSftpVersion(PTSSH_HIGHEST_SUPPORTED_SFTP_VERSION),
m_remoteChannelNum(PTSSH_BAD_CHANNEL_NUMBER),
m_pRequestMgr(0)
{

}

///////////////////////////////////////////////////////////////////////////////
PTSftp::~PTSftp(void)
{
	if (m_pRequestMgr)
	{
		if (m_pRequestMgr->isRunning())
			m_pRequestMgr->stopThread();

		delete m_pRequestMgr;
		m_pRequestMgr = NULL;
	}
}

///////////////////////////////////////////////////////////////////////////////
int32 
PTSftp::init()
{
	int32 
		result = PTSSH_SUCCESS;
	uint32
		sftpDataLen = 4;      //uint32 version
	pthread_mutex_t
		*pWaitMutex = NULL;
	pthread_cond_t
		*pWaitCond = NULL;

	//Validate channel number
	if ( ! m_pChannelMgr->isValidChannelNumber(m_CNum))
		return PTSSH_ERR_InvalidChannelNumber;

	m_pChannelMgr->getRemoteChannelNumber(m_CNum, m_remoteChannelNum );

	if ( ! m_pRequestMgr)
	{
		m_pRequestMgr = new SftpRequestMgr(m_CNum, m_pChannelMgr);
		if ( ! m_pRequestMgr)
			return PTSSH_ERR_CouldNotAllocateMemory;
	}

	//Create the request
	SftpBinaryPacket *pSBP = new SftpBinaryPacket(m_CNum);
	if ( pSBP && pSBP->init(sftpDataLen, SSH_FXP_INIT, -1, m_remoteChannelNum) == PTSSH_SUCCESS)
	{
		/**** Write the packet guts ******/
		//Set the version
		pSBP->writeUint32( m_requestedSftpVersion);

		//Send the packet off
		result = m_pChannelMgr->queueOutboundData( pSBP);
		if (result == PTSSH_SUCCESS)
		{
			BinaryPacket *pBP = NULL;

			//There should now be data to get
			result = m_pChannelMgr->getInboundData(m_CNum, &pBP, true, 0, false);
			if ( pBP && result == PTSSH_SUCCESS)
			{
				uint32 sftpDataLen = pBP->sftpDataLen();
				uint8 *pSftpData = pBP->sftpData();

				//Sanity Check
				if (  (*pSftpData) == SSH_FXP_VERSION)
				{
					m_operatingSftpVersion = PTSSH_htons32( *((uint32*)(pSftpData + 1)));
					PTLOG((LL_info, "PTsftp init'd on channel %d using SFTP version %d\n", m_CNum, m_operatingSftpVersion));

					/* Now that we have recieved our response, we can startup our request manager.
					 * If we would have started it up before sending our SSH_FXP_INIT, then we'd 
					 * incorrectly treat the response packet as a incoming request
					 */
					result = m_pRequestMgr->init();
					if ( result == PTSSH_SUCCESS)
					{
						if ( ! m_pRequestMgr->startThread())
							result = PTSFTP_E_CouldNotStartRequestMgrThread;
					}

					//Right now we ignore extension-pairs
				}
				else
				{
					PTLOG((LL_info, "PTsftp init: invalid packet type %d\n", (*pSftpData)));
					result =PTSSH_ERR_SftpBadPacketType;
				}

				delete pBP;
			}
			else
			{
				PTLOG((LL_info, "PTsftp: Error %d reading from channel %d\n", result, m_CNum));
			}
		}
		else
		{
			result = PTSSH_ERR_CouldNotAllocateMemory;
			delete pSBP;
		}
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
/*
Files are opened and created using the SSH_FXP_OPEN message.

	byte   SSH_FXP_OPEN
	uint32 request-id
	string filename [UTF-8]
	uint32        pflags
	    The `pflags' field is a bitmask. The following bits have been defined.
   		#define SSH_FXF_READ            0x00000001
   		#define SSH_FXF_WRITE           0x00000002
   		#define SSH_FXF_APPEND          0x00000004
   		#define SSH_FXF_CREAT           0x00000008
   		#define SSH_FXF_TRUNC           0x00000010
   		#define SSH_FXF_EXCL            0x00000020
	ATTRS         attrs

   The following table is provided to assist in mapping POSIX semantics
   to equivalent SFTP file open parameters:

   O_RDONLY
      desired-access = READ_DATA|READ_ATTRIBUTES
	  pflags = SSH_FXF_READ

   O_WRONLY
      desired-access = WRITE_DATA|WRITE_ATTRIBUTES
	  pflags = SSH_FXF_WRITE

   O_RDWR
      desired-access = READ_DATA|READ_ATTRIBUTES|WRITE_DATA|WRITE_ATTRIBUTES
	  pflags = SSH_FXF_READ | SSH_FXF_WRITE

   O_APPEND
      desired-access = WRITE_DATA|WRITE_ATTRIBUTES|APPEND_DATA
      flags = SSH_FXF_APPEND_DATA and or SSH_FXF_APPEND_DATA_ATOMIC
	  pflags = SSH_FXF_WRITE | SSH_FXF_APPEND

   O_CREAT
      flags = SSH_FXF_OPEN_OR_CREATE
	  pflags = SSH_FXF_CREAT

   O_TRUNC
      flags = SSH_FXF_TRUNCATE_EXISTING
	  pflags = SSH_FXF_TRUNC

   O_TRUNC|O_CREATE
      flags = SSH_FXF_CREATE_TRUNCATE
	  pflags = SSH_FXF_CREAT | SSH_FXF_TRUNC ???
*/
int32 
PTSftp::openFile(
		SftpFileHandle **ppSftpFileHandle,
		const char *fileName,
		uint32 pflags)
{
	int32 
		result = PTSSH_SUCCESS;
	SftpAttrs 
		attr( m_operatingSftpVersion);
	pthread_mutex_t
		*pWaitMutex = NULL;
	pthread_cond_t
		*pWaitCond = NULL;
	uint32
		requestID,
		sftpFlags = 0,
		sftpDataLen =
			1 +                  //byte   SSH_FXP_OPEN
       		4 +                  //uint32 request-id
       		4 + (uint32)strlen(fileName)+// string filename [UTF-8]
       		4 +                  // uint32 flags
			attr.bufferSizeNeeded();  // ATTRS  attrs
	*ppSftpFileHandle = NULL;

	//Set the attributes
	attr.permissions( FT_S_IFREG);  //Set file attribute

	//Convert the incoming POSIX flags to SFTP-friendly flags
	if ( pflags == FO_RDONLY)
		sftpFlags |= SSH_FXF_READ;
	else
	{
		if ( pflags & FO_WRONLY)
			sftpFlags |= SSH_FXF_WRITE;
		if ( pflags & FO_RDWR)
			sftpFlags |=  SSH_FXF_READ | SSH_FXF_WRITE;
		if ( pflags & FO_APPEND)
			sftpFlags |=  SSH_FXF_WRITE | SSH_FXF_APPEND;
		if ( pflags & FO_CREATE)
		{
			sftpFlags |=  SSH_FXF_CREAT;
			//Set default file creation permissions of 744
			attr.permissions( attr.permissions() | FP_USR_RWX | FP_GRP_R | FP_OTH_R);
		}
	}

	//Alert our SftpRequestMgr that we are going to be waiting on data for a new request
	result = m_pRequestMgr->createRequest(
		requestID,
		&pWaitCond,
		&pWaitMutex);
	if ( result != PTSSH_SUCCESS)
		return result;

	//Create the request
	SftpBinaryPacket *pSBP = new SftpBinaryPacket(m_CNum);
	if ( pSBP && pSBP->init(sftpDataLen, SSH_FXP_OPEN, requestID, m_remoteChannelNum) == PTSSH_SUCCESS)
	{
		Data *pData = NULL;

		/**** Write the packet guts ******/
		//Set the version
		pSBP->writeString(fileName, (uint32)strlen(fileName));
		pSBP->writeUint32(sftpFlags);
		pSBP->writeAttr( &attr);
		
		//Send the packet off
		result = m_pChannelMgr->queueOutboundData( pSBP);
		if (result == PTSSH_SUCCESS)
		{
			BinaryPacket *pBP = NULL;

			//Wait for the SftpRequestMgr to get a response to our request
			pthread_mutex_lock( pWaitMutex);
			pthread_cond_wait(pWaitCond, pWaitMutex);
			pthread_mutex_unlock( pWaitMutex);

			//There should now be data to get
			result = m_pRequestMgr->getRequestData(requestID, &pBP);
			if ( result == PTSSH_SUCCESS)
			{
				uint32 sftpDataLen = pBP->sftpDataLen();
				uint8 *pSftpData = pBP->sftpData();

				//Check and see if we were successful
				if ( *pSftpData == SSH_FXP_HANDLE)
				{
					/* The SSH_FXP_HANDLE response has the following format:
							uint32     id
							string     handle
					   where `id' is the request identifier, and `handle' is an arbitrary
					   string that identifies an open file or directory on the server.  The
					   handle is opaque to the client; the client MUST NOT attempt to
					   interpret or modify it in any way.  The length of the handle string
					   MUST NOT exceed 256 data bytes. */
					//Create the new handle from the ssh string handle
					*ppSftpFileHandle = new SftpFileHandle(
						m_pRequestMgr, 
						m_pChannelMgr, 
						m_CNum, 
						m_remoteChannelNum,
						m_operatingSftpVersion);
					if ( *ppSftpFileHandle && (*ppSftpFileHandle)->init(pSftpData + 5) != PTSSH_SUCCESS)
					{
						result = PTSSH_ERR_CouldNotAllocateMemory;

						//TODO: Close the file handle
					}
				}
				else if ( *pSftpData == SSH_FXP_STATUS)
				{
					SSH_FXP_STATUS_STRUCT statStruct;
					statStruct.pData = pSftpData;
					result = statStruct.getStatusCode();
				}
				else
				{
					/*     
					The format of the data portion of the SSH_FXP_STATUS response is as follows:
   						uint32     id
   						uint32     error/status code
   						string     error message (ISO-10646 UTF-8 [RFC-2279])
   						string     language tag (as defined in [RFC-1766])
					*/
					PTLOG((LL_error, "PTsftp openFile: Couldn not open file. Error: %d\n", PTSSH_htons32( (uint32*)(pSftpData + 5)) ));
					result = PTSFTP_E_GeneralError;
				}

				//TODO: stuff
			}
			else
			{
				PTLOG((LL_error, "PTsftp openFile: Unable to get response!\n"));
			}
		}
		else
		{
			result = PTSSH_ERR_CouldNotAllocateMemory;
			delete pSBP;
		}
	}
	else
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		delete pSBP;
	}

	//Alert the request manager that we are done with this request
	m_pRequestMgr->deleteRequest(requestID);

	return result;
}

///////////////////////////////////////////////////////////////////////////////
// A file is closed by using the SSH_FXP_CLOSE request.  Its data field
//has the following format:

//	uint32     id
//	string     handle

//where `id' is the request identifier, and `handle' is a handle
//previously returned in the response to SSH_FXP_OPEN or
//SSH_FXP_OPENDIR.  The handle becomes invalid immediately after this
//request has been sent.
///////////////////////////////////////////////////////////////////////////////
int32 
PTSftp::closeFile(SftpFileHandle **ppSftpFileHandle)
{
	int32 
		result = PTSSH_SUCCESS;
	pthread_mutex_t
		*pWaitMutex = NULL;
	pthread_cond_t
		*pWaitCond = NULL;
	uint32
		requestID,
		sftpDataLen =
			1 +                  //byte   SSH_FXP_OPEN
   			4 +                  //uint32 request-id
   			4 +                  //string     handle
			(*ppSftpFileHandle)->getHandleLen();

	//Alert our SftpRequestMgr that we are going to be waiting on data for a new request
	result = m_pRequestMgr->createRequest(
		requestID,
		&pWaitCond,
		&pWaitMutex);
	if ( result != PTSSH_SUCCESS)
		return result;

	//Create the request
	SftpBinaryPacket *pSBP = new SftpBinaryPacket(m_CNum);
	if ( pSBP && pSBP->init(sftpDataLen, SSH_FXP_CLOSE, requestID, m_remoteChannelNum) == PTSSH_SUCCESS)
	{
		/**** Write the packet guts ******/
		//Set the version
		pSBP->writeString( 
			(const char *)(*ppSftpFileHandle)->getHandleStr(), 
			(*ppSftpFileHandle)->getHandleLen());
		//Send the packet off
		result = m_pChannelMgr->queueOutboundData( pSBP);
		if (result == PTSSH_SUCCESS)
		{
			BinaryPacket *pBP = NULL;
			/* The response to this request will be a SSH_FXP_STATUS message.  One
			   should note that on some server platforms even a close can fail.
			   This can happen e.g.  if the server operating system caches writes,
			   and an error occurs while flushing cached writes during the close. */

			//Wait for the SftpRequestMgr to get a response to our request
			pthread_mutex_lock( pWaitMutex);
			pthread_cond_wait(pWaitCond, pWaitMutex);
			pthread_mutex_unlock( pWaitMutex);

			//There should now be data to get
			result = m_pRequestMgr->getRequestData(requestID, &pBP);
			if ( result == PTSSH_SUCCESS)
			{
				uint32 
					sftpDataLen = pBP->sftpDataLen();
				uint8 
					*pSftpData = pBP->sftpData();

				//Check and see if we were successful
				if ( *pSftpData == SSH_FXP_STATUS)
				{
					SSH_FXP_STATUS_STRUCT statStruct;
					statStruct.pData = pSftpData;
					/* The format of the data portion of the SSH_FXP_STATUS response is:
   						uint32     id
   						uint32     error/status code
   						string     error message (ISO-10646 UTF-8 [RFC-2279])
   						string     language tag (as defined in [RFC-1766])	*/
					if ( statStruct.getStatusCode() == SSH_FX_OK)
						result = PTSSH_SUCCESS;
					else
					{
						PTLOG((LL_error, "PTsftp closeFile: SFTP Error %d occured while trying to close file\n",
							statStruct.getStatusCode() ));
						result = PTSFTP_E_CouldNotCloseFile;
					}
				}
				else
				{
					PTLOG((LL_error, "PTsftp closeFile: Unexpected response %d (0x%02X)\n",
						pSftpData+4, pSftpData+4));
					result = PTSFTP_E_UnexpectedResponse;
				}
			}
			else
				result = PTSFTP_E_CouldNotGetResponse;
		}
	}

	delete *ppSftpFileHandle;
	*ppSftpFileHandle = NULL;

	//Alert the request manager that we are done with this request
	m_pRequestMgr->deleteRequest(requestID);

	return result;
}


///////////////////////////////////////////////////////////////////////////////
/* Files can be removed using the SSH_FXP_REMOVE message.  It has the
   following format:
   	uint32     id
   	string     filename
*/
int32 
PTSftp::deleteFile(const char *pFileName)
{
	int32 
		result = PTSSH_SUCCESS;
	pthread_mutex_t
		*pWaitMutex = NULL;
	pthread_cond_t
		*pWaitCond = NULL;
	uint32
		requestID,
		sftpDataLen =
			1 +                  //byte   SSH_FXP_REMOVE
   			4 +                  //uint32     id
			4 + (uint32)strlen(pFileName); //string filename

	//Alert our SftpRequestMgr that we are going to be waiting on data for a new request
	result = m_pRequestMgr->createRequest(
		requestID,
		&pWaitCond,
		&pWaitMutex);
	if ( result != PTSSH_SUCCESS)
		return result;

	//Create the request
	SftpBinaryPacket *pSBP = new SftpBinaryPacket(m_CNum);
	if ( pSBP && pSBP->init(sftpDataLen, SSH_FXP_REMOVE, requestID, m_remoteChannelNum) == PTSSH_SUCCESS)
	{
		/**** Write the packet guts ******/
		pSBP->writeString( pFileName, (uint32)strlen(pFileName) );

		//Send the packet off
		result = m_pChannelMgr->queueOutboundData( pSBP);
		if ( result == PTSSH_SUCCESS)
		{
			BinaryPacket *pBP = NULL;
			/* The response to this request will be a SSH_FXP_STATUS message.  One
			   should note that on some server platforms even a close can fail.
			   This can happen e.g.  if the server operating system caches writes,
			   and an error occurs while flushing cached writes during the close. */

			//Wait for the SftpRequestMgr to get a response to our request
			pthread_mutex_lock( pWaitMutex);
			pthread_cond_wait(pWaitCond, pWaitMutex);
			pthread_mutex_unlock( pWaitMutex);

			//We should now be able to get all the data for the request or detect if an error occured
			result = m_pRequestMgr->getRequestData(requestID, &pBP);
			if ( result == PTSSH_SUCCESS)
			{
				uint8
					*pSftpData = pBP->sftpData();
				if ( *pSftpData == SSH_FXP_STATUS)
				{
					SSH_FXP_STATUS_STRUCT status;
					status.pData = pSftpData;
					result = (int32) status.getStatusCode();
				}
				else
					result = PTSFTP_E_UnexpectedResponse;

				delete pBP;
			}
			else
				result = PTSFTP_E_CouldNotGetResponse;
		}
		else
			result = PTSSH_ERR_CouldNotQueuePacketForSending;
	}

	//Alert the request manager that we are done with this request
	m_pRequestMgr->deleteRequest(requestID);

	return result;
}

///////////////////////////////////////////////////////////////////////////////
/* Files (and directories) can be renamed using the SSH_FXP_RENAME
   message.  Its data is as follows:
   	uint32     id
   	string     oldpath
   	string     newpath
*/
int32 
PTSftp::renameFileOrDir(const char *pOldPath, const char *pNewPath)
{
	int32 
		result = PTSSH_SUCCESS;
	pthread_mutex_t
		*pWaitMutex = NULL;
	pthread_cond_t
		*pWaitCond = NULL;
	uint32
		requestID,
		sftpDataLen =
			1 +                  //byte   SSH_FXP_RENAME
   			4 +                  //uint32     id
			4 + (uint32)strlen(pOldPath) + //string     oldpath
			4 + (uint32)strlen(pNewPath);  //string     newpath

	//Alert our SftpRequestMgr that we are going to be waiting on data for a new request
	result = m_pRequestMgr->createRequest(
		requestID,
		&pWaitCond,
		&pWaitMutex);
	if ( result != PTSSH_SUCCESS)
		return result;

	//Create the request
	SftpBinaryPacket *pSBP = new SftpBinaryPacket(m_CNum);
	if ( pSBP && pSBP->init(sftpDataLen, SSH_FXP_RENAME, requestID, m_remoteChannelNum) == PTSSH_SUCCESS)
	{
		/**** Write the packet guts ******/
		pSBP->writeString( pOldPath, (uint32) strlen(pOldPath) );
		pSBP->writeString( pNewPath, (uint32) strlen(pNewPath) );

		//Send the packet off
		result = m_pChannelMgr->queueOutboundData( pSBP);
		if ( result == PTSSH_SUCCESS)
		{
			BinaryPacket *pBP = NULL;
			/* The response to this request will be a SSH_FXP_STATUS message.  One
			   should note that on some server platforms even a close can fail.
			   This can happen e.g.  if the server operating system caches writes,
			   and an error occurs while flushing cached writes during the close. */

			//Wait for the SftpRequestMgr to get a response to our request
			pthread_mutex_lock( pWaitMutex);
			pthread_cond_wait(pWaitCond, pWaitMutex);
			pthread_mutex_unlock( pWaitMutex);

			//We should now be able to get all the data for the request or detect if an error occured
			result = m_pRequestMgr->getRequestData(requestID, &pBP);
			if ( result == PTSSH_SUCCESS)
			{
				uint8
					*pSftpData = pBP->sftpData();
				if ( *pSftpData == SSH_FXP_STATUS)
				{
					SSH_FXP_STATUS_STRUCT status;
					status.pData = pSftpData;
					result = (int32) status.getStatusCode();
				}
				else
					result = PTSFTP_E_UnexpectedResponse;

				delete pBP;
			}
			else
				result = PTSFTP_E_CouldNotGetResponse;
		}
		else
			result = PTSSH_ERR_CouldNotQueuePacketForSending;
	}

	//Alert the request manager that we are done with this request
	m_pRequestMgr->deleteRequest(requestID);

	return result;
}

///////////////////////////////////////////////////////////////////////////////
/* New directories can be created using the SSH_FXP_MKDIR request.  It
   has the following format:
   	uint32     id
   	string     path
   	ATTRS      attrs
*/
int32 
PTSftp::makeDir(const char *pNewDir, SftpAttrs *pAttrs)
{
	int32 
		result = PTSSH_SUCCESS;
	pthread_mutex_t
		*pWaitMutex = NULL;
	pthread_cond_t
		*pWaitCond = NULL;
	uint32
		requestID,
		sftpDataLen;

	if ( ! pAttrs)
		return PTSSH_ERR_NullPointerGiven;
	
	sftpDataLen =
		1 +                  //byte   SSH_FXP_MKDIR
		4 +                  //uint32     id
		4 + (uint32)strlen(pNewDir) + //string  path
		pAttrs->bufferSizeNeeded();//ATTRS   attrs

	//Alert our SftpRequestMgr that we are going to be waiting on data for a new request
	result = m_pRequestMgr->createRequest(
		requestID,
		&pWaitCond,
		&pWaitMutex);
	if ( result != PTSSH_SUCCESS)
		return result;

	//Create the request
	SftpBinaryPacket *pSBP = new SftpBinaryPacket(m_CNum);
	if ( pSBP && pSBP->init(sftpDataLen, SSH_FXP_MKDIR, requestID, m_remoteChannelNum) == PTSSH_SUCCESS)
	{
		/**** Write the packet guts ******/
		pSBP->writeString( pNewDir, (uint32) strlen(pNewDir) );
		pSBP->writeAttr( pAttrs);

		//Send the packet off
		result = m_pChannelMgr->queueOutboundData( pSBP);
		if ( result == PTSSH_SUCCESS)
		{
			BinaryPacket *pBP = NULL;
			/* The response to this request will be a SSH_FXP_STATUS message.  One
			   should note that on some server platforms even a close can fail.
			   This can happen e.g.  if the server operating system caches writes,
			   and an error occurs while flushing cached writes during the close. */

			//Wait for the SftpRequestMgr to get a response to our request
			pthread_mutex_lock( pWaitMutex);
			pthread_cond_wait(pWaitCond, pWaitMutex);
			pthread_mutex_unlock( pWaitMutex);

			//We should now be able to get all the data for the request or detect if an error occured
			result = m_pRequestMgr->getRequestData(requestID, &pBP);
			if ( result == PTSSH_SUCCESS)
			{
				uint8
					*pSftpData = pBP->sftpData();
				if ( *pSftpData == SSH_FXP_STATUS)
				{
					SSH_FXP_STATUS_STRUCT status;
					status.pData = pSftpData;
					result = (int32) status.getStatusCode();
				}
				else
					result = PTSFTP_E_UnexpectedResponse;

				delete pBP;
			}
			else
				result = PTSFTP_E_CouldNotGetResponse;
		}
		else
			result = PTSSH_ERR_CouldNotQueuePacketForSending;
	}

	//Alert the request manager that we are done with this request
	m_pRequestMgr->deleteRequest(requestID);

	return result;
}

///////////////////////////////////////////////////////////////////////////////
/* New directories can be deleted using the SSH_FXP_RMDIR request.  It
   has the following format:
   	uint32     id
   	string     path
*/
int32 
PTSftp::deleteDir(const char *pPath)
{
	int32 
		result = PTSSH_SUCCESS;
	pthread_mutex_t
		*pWaitMutex = NULL;
	pthread_cond_t
		*pWaitCond = NULL;
	uint32
		requestID,
		sftpDataLen =
			1 +                  //byte   SSH_FXP_RMDIR
   			4 +                  //uint32     id
			4 + (uint32)strlen(pPath); //string  path

	//Alert our SftpRequestMgr that we are going to be waiting on data for a new request
	result = m_pRequestMgr->createRequest(
		requestID,
		&pWaitCond,
		&pWaitMutex);
	if ( result != PTSSH_SUCCESS)
		return result;

	//Create the request
	SftpBinaryPacket *pSBP = new SftpBinaryPacket(m_CNum);
	if ( pSBP && pSBP->init(sftpDataLen, SSH_FXP_RMDIR, requestID, m_remoteChannelNum) == PTSSH_SUCCESS)
	{
		/**** Write the packet guts ******/
		pSBP->writeString( pPath, (uint32) strlen(pPath) );

		//Send the packet off
		result = m_pChannelMgr->queueOutboundData( pSBP);
		if ( result == PTSSH_SUCCESS)
		{
			BinaryPacket *pBP = NULL;
			/* The response to this request will be a SSH_FXP_STATUS message.  One
			   should note that on some server platforms even a close can fail.
			   This can happen e.g.  if the server operating system caches writes,
			   and an error occurs while flushing cached writes during the close. */

			//Wait for the SftpRequestMgr to get a response to our request
			pthread_mutex_lock( pWaitMutex);
			pthread_cond_wait(pWaitCond, pWaitMutex);
			pthread_mutex_unlock( pWaitMutex);

			//We should now be able to get all the data for the request or detect if an error occured
			result = m_pRequestMgr->getRequestData(requestID, &pBP);
			if ( result == PTSSH_SUCCESS)
			{
				uint8
					*pSftpData = pBP->sftpData();
				if ( *pSftpData == SSH_FXP_STATUS)
				{
					SSH_FXP_STATUS_STRUCT status;
					status.pData = pSftpData;
					result = (int32) status.getStatusCode();
				}
				else
					result = PTSFTP_E_UnexpectedResponse;

				delete pBP;
			}
			else
				result = PTSFTP_E_CouldNotGetResponse;
		}
		else
			result = PTSSH_ERR_CouldNotQueuePacketForSending;
	}

	//Alert the request manager that we are done with this request
	m_pRequestMgr->deleteRequest(requestID);

	return result;
}

///////////////////////////////////////////////////////////////////////////////
/* The SSH_FXP_OPENDIR opens a directory for reading.  It has the
   following format:
   	uint32     id
   	string     path
*/
int32 
PTSftp::openDir(
		SftpDirHandle **ppSftpDirHandle,
		const char *pPath)
{
	int32 
		result = PTSSH_SUCCESS;
	pthread_mutex_t
		*pWaitMutex = NULL;
	pthread_cond_t
		*pWaitCond = NULL;
	uint32
		requestID,
		sftpDataLen =
			1 +                  //byte   SSH_FXP_OPENDIR
   			4 +                  //uint32     id
			4 + (uint32)strlen(pPath); //string  path
	*ppSftpDirHandle = NULL;

	//Alert our SftpRequestMgr that we are going to be waiting on data for a new request
	result = m_pRequestMgr->createRequest(
		requestID,
		&pWaitCond,
		&pWaitMutex);
	if ( result != PTSSH_SUCCESS)
		return result;

	//Create the request
	SftpBinaryPacket *pSBP = new SftpBinaryPacket(m_CNum);
	if ( pSBP && pSBP->init(sftpDataLen, SSH_FXP_OPENDIR, requestID, m_remoteChannelNum) == PTSSH_SUCCESS)
	{
		/**** Write the packet guts ******/
		pSBP->writeString( pPath, (uint32) strlen(pPath) );

		//Send the packet off
		result = m_pChannelMgr->queueOutboundData( pSBP);
		if ( result == PTSSH_SUCCESS)
		{
			BinaryPacket *pBP = NULL;
			/* The response to this request will be a SSH_FXP_STATUS message.  One
			   should note that on some server platforms even a close can fail.
			   This can happen e.g.  if the server operating system caches writes,
			   and an error occurs while flushing cached writes during the close. */

			//Wait for the SftpRequestMgr to get a response to our request
			pthread_mutex_lock( pWaitMutex);
			pthread_cond_wait(pWaitCond, pWaitMutex);
			pthread_mutex_unlock( pWaitMutex);

			//We should now be able to get all the data for the request or detect if an error occured
			result = m_pRequestMgr->getRequestData(requestID, &pBP);
			if ( result == PTSSH_SUCCESS)
			{
				uint8
					*pSftpData = pBP->sftpData();
				if ( *pSftpData == SSH_FXP_HANDLE)
				{
					/* The SSH_FXP_HANDLE response has the following format:
							uint32     id
							string     handle
					   where `id' is the request identifier, and `handle' is an arbitrary
					   string that identifies an open file or directory on the server.  The
					   handle is opaque to the client; the client MUST NOT attempt to
					   interpret or modify it in any way.  The length of the handle string
					   MUST NOT exceed 256 data bytes. */
					//Create the new handle from the ssh string handle
					*ppSftpDirHandle = new SftpDirHandle(
						m_pRequestMgr, 
						m_pChannelMgr, 
						m_CNum, 
						m_remoteChannelNum,
						m_operatingSftpVersion);
					if ( *ppSftpDirHandle && (*ppSftpDirHandle)->init(pSftpData + 5) != PTSSH_SUCCESS)
					{
						result = PTSSH_ERR_CouldNotAllocateMemory;

						//TODO: Close the dir handle
					}
				}
				else
					result = PTSFTP_E_UnexpectedResponse;

				delete pBP;
			}
			else
				result = PTSFTP_E_CouldNotGetResponse;
		}
		else
			result = PTSSH_ERR_CouldNotQueuePacketForSending;
	}

	//Alert the request manager that we are done with this request
	m_pRequestMgr->deleteRequest(requestID);

	return result;
}

///////////////////////////////////////////////////////////////////////////////
/* When the client no longer wishes to read more names from the
   directory, it SHOULD call SSH_FXP_CLOSE for the handle.  The handle
   should be closed regardless of whether an error has occurred or not.
*/
int32 
PTSftp::closeDir(SftpDirHandle **ppSftpDirHandle)
{
	int32 
		result = PTSSH_SUCCESS;
	pthread_mutex_t
		*pWaitMutex = NULL;
	pthread_cond_t
		*pWaitCond = NULL;
	uint32
		requestID,
		sftpDataLen =
			1 +                  //byte   SSH_FXP_CLOSE
   			4 +                  //uint32 request-id
   			4 +                  //string     handle
			(*ppSftpDirHandle)->getHandleLen();

	//Alert our SftpRequestMgr that we are going to be waiting on data for a new request
	result = m_pRequestMgr->createRequest(
		requestID,
		&pWaitCond,
		&pWaitMutex);
	if ( result != PTSSH_SUCCESS)
		return result;

	//Create the request
	SftpBinaryPacket *pSBP = new SftpBinaryPacket(m_CNum);
	if ( pSBP && pSBP->init(sftpDataLen, SSH_FXP_CLOSE, requestID, m_remoteChannelNum) == PTSSH_SUCCESS)
	{
		/**** Write the packet guts ******/
		//Set the version
		pSBP->writeString( 
			(const char *)(*ppSftpDirHandle)->getHandleStr(), 
			(*ppSftpDirHandle)->getHandleLen());
		//Send the packet off
		result = m_pChannelMgr->queueOutboundData( pSBP);
		if (result == PTSSH_SUCCESS)
		{
			BinaryPacket *pBP = NULL;
			/* The response to this request will be a SSH_FXP_STATUS message.  One
			   should note that on some server platforms even a close can fail.
			   This can happen e.g.  if the server operating system caches writes,
			   and an error occurs while flushing cached writes during the close. */

			//Wait for the SftpRequestMgr to get a response to our request
			pthread_mutex_lock( pWaitMutex);
			pthread_cond_wait(pWaitCond, pWaitMutex);
			pthread_mutex_unlock( pWaitMutex);

			//There should now be data to get
			result = m_pRequestMgr->getRequestData(requestID, &pBP);
			if ( result == PTSSH_SUCCESS)
			{
				uint32 
					sftpDataLen = pBP->sftpDataLen();
				uint8 
					*pSftpData = pBP->sftpData();

				//Check and see if we were successful
				if ( *pSftpData == SSH_FXP_STATUS)
				{
					SSH_FXP_STATUS_STRUCT statStruct;
					statStruct.pData = pSftpData;
					/* The format of the data portion of the SSH_FXP_STATUS response is:
   						uint32     id
   						uint32     error/status code
   						string     error message (ISO-10646 UTF-8 [RFC-2279])
   						string     language tag (as defined in [RFC-1766])	*/
					if ( statStruct.getStatusCode() == SSH_FX_OK)
						result = PTSSH_SUCCESS;
					else
					{
						PTLOG((LL_error, "PTsftp closeDir: SFTP Error %d occured while trying to close a directory\n",
							statStruct.getStatusCode() ));
						result = PTSFTP_E_CouldNotCloseFile;
					}
				}
				else
				{
					PTLOG((LL_error, "PTsftp closeDir: Unexpected response %d (0x%02X))\n",
						pSftpData+4, pSftpData+4));
					result = PTSFTP_E_UnexpectedResponse;
				}
			}
			else
				result = PTSFTP_E_CouldNotGetResponse;
		}
	}

	delete *ppSftpDirHandle;
	*ppSftpDirHandle = NULL;

	//Alert the request manager that we are done with this request
	m_pRequestMgr->deleteRequest(requestID);

	return result;
}

///////////////////////////////////////////////////////////////////////////////
/* To retrieve the attributes for a named file use
   SSH_FXP_STAT, SSH_FXP_LSTAT requests.

    SSH_FXP_STAT and SSH_FXP_LSTAT only differ in that SSH_FXP_STAT
   follows symbolic links on the server, whereas SSH_FXP_LSTAT does not
   follow symbolic links.  Both have the same format:
   	uint32     id
   	string     path
*/
int32 
PTSftp::getFileAttributes(const char *pPath, bool bFollowSymLinks, SftpAttrs *pAttrs)
{
	int32 
		result = PTSSH_SUCCESS;
	pthread_mutex_t
		*pWaitMutex = NULL;
	pthread_cond_t
		*pWaitCond = NULL;
	uint32
		requestID,
		sftpDataLen =
			1 +                  //byte   SSH_FXP_STAT -or- SSH_FXP_LSTAT
   			4 +                  //uint32     id
			4 + (uint32)strlen(pPath); //string  path
	uint8
		sftpType = bFollowSymLinks? SSH_FXP_STAT : SSH_FXP_LSTAT;

	if ( ! pAttrs || ! pPath)
		return PTSSH_ERR_NullPointerGiven;

	//Make sure the object is all squeaky clean!
	memset( pAttrs, 0x0, sizeof(SftpAttrs));

	//Alert our SftpRequestMgr that we are going to be waiting on data for a new request
	result = m_pRequestMgr->createRequest(
		requestID,
		&pWaitCond,
		&pWaitMutex);
	if ( result != PTSSH_SUCCESS)
		return result;

	//Create the request
	SftpBinaryPacket *pSBP = new SftpBinaryPacket(m_CNum);
	if ( pSBP && pSBP->init(sftpDataLen, sftpType, requestID, m_remoteChannelNum) == PTSSH_SUCCESS)
	{
		/**** Write the packet guts ******/
		pSBP->writeString( pPath, (uint32) strlen(pPath) );

		//Send the packet off
		result = m_pChannelMgr->queueOutboundData( pSBP);
		if ( result == PTSSH_SUCCESS)
		{
			BinaryPacket *pBP = NULL;
			/* The response to this request will be a SSH_FXP_STATUS message.  One
			   should note that on some server platforms even a close can fail.
			   This can happen e.g.  if the server operating system caches writes,
			   and an error occurs while flushing cached writes during the close. */

			//Wait for the SftpRequestMgr to get a response to our request
			pthread_mutex_lock( pWaitMutex);
			pthread_cond_wait(pWaitCond, pWaitMutex);
			pthread_mutex_unlock( pWaitMutex);

			//We should now be able to get all the data for the request or detect if an error occured
			result = m_pRequestMgr->getRequestData(requestID, &pBP);
			if ( result == PTSSH_SUCCESS)
			{
				uint8
					*pSftpData = pBP->sftpData();
				if ( *pSftpData == SSH_FXP_ATTRS)
				{
					pAttrs->getFromPacketBuffer(pSftpData + 5);
				}
				else if ( *pSftpData == SSH_FXP_STATUS)
				{
					SSH_FXP_STATUS_STRUCT status;
					status.pData = pSftpData;
					result = (int32) status.getStatusCode();
				}
				else
					result = PTSFTP_E_UnexpectedResponse;

				delete pBP;
			}
			else
				result = PTSFTP_E_CouldNotGetResponse;
		}
		else
			result = PTSSH_ERR_CouldNotQueuePacketForSending;
	}

	//Alert the request manager that we are done with this request
	m_pRequestMgr->deleteRequest(requestID);

	return result;
}

///////////////////////////////////////////////////////////////////////////////
/* The SSH_FXP_SYMLINK request will create a symbolic link on the
   server.  It is of the following format

   	uint32     id
   	string     linkpath
   	string     targetpath

   where `id' is the request identifier, `linkpath' specifies the path
   name of the symlink to be created and `targetpath' specifies the
   target of the symlink.  The server shall respond with a
   SSH_FXP_STATUS indicating either success (SSH_FX_OK) or an error
   condition.
*/
int32 
PTSftp::createSymLink(const char *pLinkPath, const char *pTargetPath)
{
	int32 
		result = PTSSH_SUCCESS;
	pthread_mutex_t
		*pWaitMutex = NULL;
	pthread_cond_t
		*pWaitCond = NULL;
	uint32
		requestID,
		sftpDataLen =
			1 +                  //byte   SSH_FXP_SYMLINK
   			4 +                  //uint32     id
			4 + (uint32)strlen(pLinkPath) +//string     linkpath
			4 + (uint32)strlen(pTargetPath); //string     targetpath

	//Alert our SftpRequestMgr that we are going to be waiting on data for a new request
	result = m_pRequestMgr->createRequest(
		requestID,
		&pWaitCond,
		&pWaitMutex);
	if ( result != PTSSH_SUCCESS)
		return result;

	//Create the request
	SftpBinaryPacket *pSBP = new SftpBinaryPacket(m_CNum);
	if ( pSBP && pSBP->init(sftpDataLen, SSH_FXP_SYMLINK, requestID, m_remoteChannelNum) == PTSSH_SUCCESS)
	{
		/**** Write the packet guts ******/
		pSBP->writeString( pLinkPath, (uint32) strlen(pLinkPath) );
		pSBP->writeString( pTargetPath, (uint32) strlen(pTargetPath) );

		//Send the packet off
		result = m_pChannelMgr->queueOutboundData( pSBP);
		if ( result == PTSSH_SUCCESS)
		{
			BinaryPacket *pBP = NULL;
			/* The response to this request will be a SSH_FXP_STATUS message.  One
			   should note that on some server platforms even a close can fail.
			   This can happen e.g.  if the server operating system caches writes,
			   and an error occurs while flushing cached writes during the close. */

			//Wait for the SftpRequestMgr to get a response to our request
			pthread_mutex_lock( pWaitMutex);
			pthread_cond_wait(pWaitCond, pWaitMutex);
			pthread_mutex_unlock( pWaitMutex);

			//We should now be able to get all the data for the request or detect if an error occured
			result = m_pRequestMgr->getRequestData(requestID, &pBP);
			if ( result == PTSSH_SUCCESS)
			{
				uint8
					*pSftpData = pBP->sftpData();
				if ( *pSftpData == SSH_FXP_STATUS)
				{
					SSH_FXP_STATUS_STRUCT status;
					status.pData = pSftpData;
					result = (int32) status.getStatusCode();
				}
				else
					result = PTSFTP_E_UnexpectedResponse;

				delete pBP;
			}
			else
				result = PTSFTP_E_CouldNotGetResponse;
		}
		else
			result = PTSSH_ERR_CouldNotQueuePacketForSending;
	}

	//Alert the request manager that we are done with this request
	m_pRequestMgr->deleteRequest(requestID);

	return result;
}


#endif /* PTSSH_SFTP */