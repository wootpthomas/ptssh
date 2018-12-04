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
#include "SftpFileHandle.h"

#ifdef PTSSH_SFTP

#include "SSH2Types.h"
#include "SftpBinaryPacket.h"
#include "SftpRequestMgr.h"
#include "ChannelManager.h"
#include "Utility.h"
#include "PTsshLog.h"
#include "PTSftp.h"

#include <string.h>
#include <assert.h>

#if defined(WIN32)
#  if defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
#    define _CRTDBG_MAP_ALLOC
#    include <stdlib.h>
#    include <crtdbg.h>
#    define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#    define new DEBUG_NEW
#  endif
#endif


/**
TODO: Future function condensing is possible. Most of the SFTP related functions can
be compressed to use a general type of packaging and sending off...
typedef struct {
	SSHType type;
	union {
		struct {
			uint64 integer64;
		};
		struct {
			uint32 integer32;
		};
		struct {
			uint8  byte;
		};
		struct {
			uint8  boolean;
		};
		struct {
			uint8 *pStr;
		};
	} data;
}  SSH_DATA_OBJ;
*/


///////////////////////////////////////////////////////////////////////////////
SftpFileHandle::SftpFileHandle(
							   SftpRequestMgr * const pRequestMgr, 
							   ChannelManager * const pChannelMgr,
							   uint32 cNum,
							   uint32 remoteChannelNum,
							   uint8 sftpVer):
SftpHandle(pRequestMgr, pChannelMgr, cNum, remoteChannelNum, sftpVer),
m_fileWriteOffset(0),
m_attrs(sftpVer),
bFileStatsSet(false)
{

}

///////////////////////////////////////////////////////////////////////////////
SftpFileHandle::~SftpFileHandle()
{

}

///////////////////////////////////////////////////////////////////////////////
/* Once a file has been opened, it can be read using the SSH_FXP_READ
   message, which has the following format:

   	uint32     id
   	string     handle
   	uint64     offset
   	uint32     len

   where `id' is the request identifier, `handle' is an open file handle
   returned by SSH_FXP_OPEN, `offset' is the offset (in bytes) relative
   to the beginning of the file from where to start reading, and `len'
   is the maximum number of bytes to read.

   In response to this request, the server will read as many bytes as it
   can from the file (up to `len'), and return them in a SSH_FXP_DATA
   message. If an error occurs or EOF is encountered before reading any
   data, the server will respond with SSH_FXP_STATUS.  For normal disk
   files, it is guaranteed that this will read the specified number of
   bytes, or up to end of file.  For e.g.  device files this may return
   fewer bytes than requested.
*/
int32 
SftpFileHandle::read(uint8 *pBuf, uint32 bufLen, uint64 offset, uint32 &bytesRead)
{
	int32 
		result = PTSSH_SUCCESS;
	pthread_mutex_t
		*pWaitMutex = NULL;
	pthread_cond_t
		*pWaitCond = NULL;
	bool
		bErrorOccured = false;
	uint32
		requestID,
		bytesToRead = 0,
		sftpDataLen =
			1 +                  //byte   SSH_FXP_OPEN
   			4 +                  //uint32 request-id
   			4 + m_handleStrLen + //string handle
			8 +                  //uint64 offset
			4;                   //uint32 len
	bytesRead = 0;

	/* If we haven't already gotten the file stats, get them now. We will base our
	 * transfer technique on the file size */
	if ( ! bFileStatsSet)
	{
		result = getFileAttributes();
		if ( result != PTSSH_SUCCESS)
			return result;
	}

	while ( bytesRead < m_attrs.fileSize() && bytesRead < bufLen && ! bErrorOccured )
	{
		//Alert our SftpRequestMgr that we are going to be waiting on data for a new request
		result = m_pRequestMgr->createRequest(
			requestID,
			&pWaitCond,
			&pWaitMutex);
		if ( result != PTSSH_SUCCESS)
			return result;

		//Create the request
		SftpBinaryPacket *pSBP = new SftpBinaryPacket(m_cNum);
		if ( pSBP && pSBP->init(sftpDataLen, SSH_FXP_READ, requestID, m_remoteChannelNum) == PTSSH_SUCCESS)
		{
			/**** Write the packet guts ******/
			pSBP->writeString( (const char *)m_pHandleStr, m_handleStrLen);
			pSBP->writeUint64( offset + bytesRead);
			pSBP->writeUint32( bufLen);

			//Send the packet off
			result = m_pChannelMgr->queueOutboundData( pSBP);
			if ( result == PTSSH_SUCCESS)
			{
				uint32 bytesInRequest = 0;
				/* The response to this request will be a SSH_FXP_STATUS message.  One
				   should note that on some server platforms even a close can fail.
				   This can happen e.g.  if the server operating system caches writes,
				   and an error occurs while flushing cached writes during the close. */

				//Wait for the SftpRequestMgr to get a response to our request
				pthread_mutex_lock( pWaitMutex);
				pthread_cond_wait(pWaitCond, pWaitMutex);
				pthread_mutex_unlock( pWaitMutex);

				//We should now be able to get all the data for the request or detect if an error occured
				result = readRequestDataIntoBuffer(
					requestID,
					pBuf + bytesRead,
					pBuf + bufLen,
					bytesInRequest);
				if ( result == PTSSH_SUCCESS)
				{
					bytesRead += bytesInRequest;
				}
				else
				{
					bErrorOccured = true;
					result = PTSFTP_E_CouldNotGetResponse;
				}
			}
			else
			{
				bErrorOccured = true;
				delete pSBP;
				result = PTSSH_ERR_CouldNotQueuePacketForSending;
			}
		}

		//Alert the request manager that we are done with this request
		m_pRequestMgr->deleteRequest(requestID);
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
/* Writing to a file is achieved using the SSH_FXP_WRITE message, which
   has the following format:
   	uint32     id
   	string     handle
   	uint64     offset
   	string     data
*/
int32 
SftpFileHandle::write(const uint8 *pBuf, uint32 bufLen)
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
			1 +                  //byte   SSH_FXP_WRITE
   			4 +                  //uint32     id
   			4 + m_handleStrLen + //string     handle
			8 +                  //uint64     offset
			4 + bufLen;          //string     data

	//Alert our SftpRequestMgr that we are going to be waiting on data for a new request
	result = m_pRequestMgr->createRequest(
		requestID,
		&pWaitCond,
		&pWaitMutex);
	if ( result != PTSSH_SUCCESS)
		return result;

	//Create the request
	SftpBinaryPacket *pSBP = new SftpBinaryPacket(m_cNum);
	if ( pSBP && pSBP->init(sftpDataLen, SSH_FXP_WRITE, requestID, m_remoteChannelNum) == PTSSH_SUCCESS)
	{
		/**** Write the packet guts ******/
		pSBP->writeString( (const char *)m_pHandleStr, m_handleStrLen);
		pSBP->writeUint64( m_fileWriteOffset );
		pSBP->writeString( (const char *)pBuf, bufLen);

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
					if ( result == SSH_FX_OK)
						m_fileWriteOffset += bufLen;
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
/* SSH_FXP_FSTAT differs from the others in that it returns status
   information for an open file (identified by the file handle).  Its
   format is as follows:

   	uint32     id
   	string     handle
*/
int32 
SftpFileHandle::getFileAttributes(SftpAttrs *pAttrs)
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
			1 +                  //byte   SSH_FXP_FSTAT
   			4 + m_handleStrLen;  //string handle

	//Alert our SftpRequestMgr that we are going to be waiting on data for a new request
	result = m_pRequestMgr->createRequest(
		requestID,
		&pWaitCond,
		&pWaitMutex);
	if ( result != PTSSH_SUCCESS)
		return result;

	//Create the request
	SftpBinaryPacket *pSBP = new SftpBinaryPacket(m_cNum);
	if ( pSBP && pSBP->init(sftpDataLen, SSH_FXP_FSTAT, requestID, m_remoteChannelNum) == PTSSH_SUCCESS)
	{
		/**** Write the packet guts ******/
		pSBP->writeString( (const char *)m_pHandleStr, m_handleStrLen);

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
					m_attrs.getFromPacketBuffer(pSftpData + 5);
					bFileStatsSet = true;
				}
				else if ( *pSftpData == SSH_FXP_STATUS)
				{
					SSH_FXP_STATUS_STRUCT *pStatus = (SSH_FXP_STATUS_STRUCT*)pSftpData;
					result = (int32) pStatus->getStatusCode();
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

	//IF we were given a pointer, copy the data
	if ( pAttrs)
		memcpy( pAttrs, &m_attrs, sizeof(SftpAttrs));

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32 
SftpFileHandle::readRequestDataIntoBuffer(uint32 requestID, uint8 *pBuf, uint8 *pBufEnd, uint32 &bytesInRequest)
{
	BinaryPacket *pBP = NULL;
	int32 
		result = m_pRequestMgr->getRequestData(requestID, &pBP);
	bytesInRequest = 0;
	if ( result == PTSSH_SUCCESS)
	{
		uint8 
			*pSftpData = pBP->sftpData();

		//Check and see if we were successful
		if ( *pSftpData == SSH_FXP_DATA)
		{
			uint32 
				totalSftpBytesToRead,
				sftpDataLen,
				ctr = 1;
			pSftpData += 5;

			//This is the total number of bytes that will be sent over for this request
			totalSftpBytesToRead = PTSSH_htons32( (uint32*)pSftpData);

			//PTLOG((LL_debug3, "Request %d, total dataLen %d\n", requestID, totalSftpBytesToRead));
						
			//Get the length of bytes in this packet
			sftpDataLen = pBP->getChannelDataLen() - 13;

			//PTLOG((LL_debug3, "Request %d, data packet %d len=%d:\n", requestID, ctr++, sftpDataLen));

			pSftpData += 4;
			memcpy(pBuf, pSftpData, sftpDataLen);
			bytesInRequest += sftpDataLen;

			//Done with this packet
			delete pBP;
			pBP = NULL;
			

			//Read the rest of the bytes in the other packets if needed
			while ( bytesInRequest < totalSftpBytesToRead)
			{
				result = m_pRequestMgr->getRequestData(requestID, &pBP);
				if ( result == PTSSH_SUCCESS)
				{
					uint8
						*pCD = pBP->getChannelData();
					uint32
						cDataLen = pBP->getChannelDataLen();

					//PTLOG((LL_debug3, "Request %d, data packet %d len=%d:\n", requestID, ctr++, cDataLen));

					if ((pBuf + bytesInRequest + cDataLen) > pBufEnd) {
						PTLOG((LL_error, "Went over the end of the buffer by %d bytes\n",
							(pBuf + bytesInRequest + cDataLen) - pBufEnd));
					}

					//Make sure we aren;t going to write past the end of the buffer
					assert( (pBuf + bytesInRequest + cDataLen) <= pBufEnd );

					//Copy bytes
					memcpy(pBuf + bytesInRequest, pCD, cDataLen);

					//Get the length of bytes in this packet
					bytesInRequest += cDataLen;

					//Done with this packet
					delete pBP;
					pBP = NULL;
				}
				else
				{
					PTLOG((LL_error, "SftpFileHandle: Error while trying to read request's data: %d\n", result));
					break;
				}
			}

			assert(bytesInRequest == totalSftpBytesToRead);
		}
		else
			result = PTSFTP_E_UnexpectedResponse;
	}
	else
		result = PTSFTP_E_CouldNotGetResponse;

	return result;
}


#endif