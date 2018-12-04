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
#include "SftpDirHandle.h"

#ifdef PTSSH_SFTP

#include "SSH2Types.h"
#include "SftpBinaryPacket.h"
#include "SftpRequestMgr.h"
#include "ChannelManager.h"
#include "Utility.h"
#include "PTsshLog.h"
#include "PTSftp.h"
#include "SftpHandle.h"

#include <string.h>

#if defined(WIN32)
#  if defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
#    define _CRTDBG_MAP_ALLOC
#    include <stdlib.h>
#    include <crtdbg.h>
#    define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#    define new DEBUG_NEW
#  endif
#endif

///////////////////////////////////////////////////////////////////////////////
SftpDirHandle::SftpDirHandle(
							   SftpRequestMgr * const pRequestMgr, 
							   ChannelManager * const pChannelMgr,
							   uint32 cNum,
							   uint32 remoteChannelNum,
							   uint8 sftpVer):
SftpHandle(pRequestMgr, pChannelMgr, cNum, remoteChannelNum, sftpVer)
{

}

///////////////////////////////////////////////////////////////////////////////
SftpDirHandle::~SftpDirHandle()
{

}

///////////////////////////////////////////////////////////////////////////////
/* Once the directory has been successfully opened, files (and
   directories) contained in it can be listed using SSH_FXP_READDIR
   requests.  These are of the format

   	uint32     id
   	string     handle

   where `id' is the request identifier, and `handle' is a handle
   returned by SSH_FXP_OPENDIR.  (It is a protocol error to attempt to
   use an ordinary file handle returned by SSH_FXP_OPEN.)
***********************
    The SSH_FXP_NAME response has the following format:
   	uint32     id
   	uint32     count
   	repeats count times:
   		string     filename
   		string     longname
   		ATTRS      attrs
   where `id' is the request identifier, `count' is the number of names
   returned in this response, and the remaining fields repeat `count'
   times (so that all three fields are first included for the first
   file, then for the second file, etc).  In the repeated part,
   `filename' is a file name being returned (for SSH_FXP_READDIR, it
   will be a relative name within the directory, without any path
   components; for SSH_FXP_REALPATH it will be an absolute path name),
   `longname' is an expanded format for the file name, similar to what
   is returned by "ls -l" on Unix systems, and `attrs' is the attributes
   of the file as described in Section ``File Attributes''.
*/
int32 
SftpDirHandle::readDir(DirectoryItem **ppDI, uint32 &itemCount)
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
			1 +                  //byte   SSH_FXP_READDIR
   			4 +                  //uint32 request-id
   			4 + m_handleStrLen;  //string handle
	*ppDI = NULL;
	itemCount = 0;


	//Alert our SftpRequestMgr that we are going to be waiting on data for a new request
	result = m_pRequestMgr->createRequest(
		requestID,
		&pWaitCond,
		&pWaitMutex);
	if ( result != PTSSH_SUCCESS)
		return result;

	//Create the request
	SftpBinaryPacket *pSBP = new SftpBinaryPacket(m_cNum);
	if ( pSBP && pSBP->init(sftpDataLen, SSH_FXP_READDIR, requestID, m_remoteChannelNum) == PTSSH_SUCCESS)
	{
		/**** Write the packet guts ******/
		pSBP->writeString( (const char *)m_pHandleStr, m_handleStrLen);

		//Send the packet off
		result = m_pChannelMgr->queueOutboundData( pSBP);
		if ( result == PTSSH_SUCCESS)
		{
			uint32 
				bytesInRequest = 0;
			BinaryPacket 
				*pBP = NULL;
			/* The response to this request will be a SSH_FXP_STATUS message.  One
			   should note that on some server platforms even a close can fail.
			   This can happen e.g.  if the server operating system caches writes,
			   and an error occurs while flushing cached writes during the close. */

			//Wait for the SftpRequestMgr to get a response to our request
			pthread_mutex_lock( pWaitMutex);
			pthread_cond_wait(pWaitCond, pWaitMutex);
			pthread_mutex_unlock( pWaitMutex);

			result = m_pRequestMgr->getRequestData(requestID, &pBP);
			if ( result == PTSSH_SUCCESS)
			{
				uint8
					*pSftpData = pBP->sftpData();
				uint32
					sftpDataLen = pBP->sftpDataLen();
				if ( *pSftpData == SSH_FXP_NAME)
				{
					pSftpData += 5;
					itemCount = PTSSH_htons32( (uint32*)pSftpData);
					// = new DirectoryItem[numberOfItems];
					*ppDI = new DirectoryItem[itemCount]();
					if (*ppDI)
					{
						//Zero out the entire array
						memset( *ppDI, 0x0, sizeof(DirectoryItem) * itemCount);

						//Move pointer to first item start
						pSftpData += 4;

						//For each directory item, copy it into our structure
						for (uint32 i = 0; i < itemCount; i++)
						{
							//For slightly less typing
							DirectoryItem *pDI = &(*ppDI)[i];

							pDI->fileNameLen = PTSSH_htons32( (uint32*)pSftpData);
							pSftpData += 4;
							pDI->pFileName = new char[pDI->fileNameLen + 1];  //Leave room for a nice NULL char
							if ( pDI->pFileName)
							{
								memcpy(pDI->pFileName, pSftpData, pDI->fileNameLen);
								pDI->pFileName[pDI->fileNameLen] = 0x0;
							}
							pSftpData += pDI->fileNameLen;

							pDI->longFileNameLen = PTSSH_htons32( (uint32*)pSftpData);
							pSftpData += 4;
							pDI->pLongFileName = new char[pDI->longFileNameLen + 1];  //Leave room for a nice NULL char
							if ( pDI->pLongFileName)
							{
								memcpy(pDI->pLongFileName, pSftpData, pDI->longFileNameLen);
								pDI->pLongFileName[pDI->longFileNameLen] = 0x0;
							}
							pSftpData += pDI->longFileNameLen;

							pDI->attrs.getFromPacketBuffer(pSftpData);
							pSftpData += pDI->attrs.bufferSizeNeeded();
						}
					}
					else
						result = PTSSH_ERR_CouldNotAllocateMemory;

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
		{
			bErrorOccured = true;
			delete pSBP;
			result = PTSSH_ERR_CouldNotQueuePacketForSending;
		}
	}

	//Alert the request manager that we are done with this request
	m_pRequestMgr->deleteRequest(requestID);

	return result;
}

#endif /* PTSSH_SFTP */