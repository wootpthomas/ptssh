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
#include "SftpRequestMgr.h"
#include "PTsshConfig.h"
#include "ChannelManager.h"
#include "PTsshLog.h"
#include "BinaryPacket.h"
#include <pthread.h>
#include "SSH2Types.h"
#include "LinkedList.h"

#ifdef PTSSH_SFTP

///////////////////////////////////////////////////////////////////////////////
SftpRequestMgr::SftpRequestMgr(uint32 cNum, ChannelManager * const pChannelMgr):
m_cNum(cNum),
m_pChannelMgr(pChannelMgr),
m_requestID(0),
m_pReqList(0)
{

}

///////////////////////////////////////////////////////////////////////////////
SftpRequestMgr::~SftpRequestMgr()
{
	RequestNode *pRN = NULL;

	pthread_mutex_destroy( &m_requestIdMutex);

	pthread_mutex_lock( &m_reqListMutex);
		while (m_pReqList->size() > 0)
		{
			pRN = (RequestNode *) m_pReqList->removeFirst();
			pthread_cond_destroy(  &pRN->condVar);
			pthread_mutex_destroy( &pRN->mutex);
			delete pRN;
		}
	pthread_mutex_unlock( &m_reqListMutex);

	pthread_mutex_destroy( &m_reqListMutex);
}

///////////////////////////////////////////////////////////////////////////////
int32 
SftpRequestMgr::init()
{
	int32 result = PTSSH_SUCCESS;

	if (pthread_mutex_init( &m_requestIdMutex, 0) != 0)
		return PTSSH_ERR_CouldNotAllocateMemory;
	if (pthread_mutex_init( &m_reqListMutex, 0) != 0)
		return PTSSH_ERR_CouldNotAllocateMemory;

	m_pReqList = new LinkedList();
	if ( ! m_pReqList)
		return PTSSH_ERR_CouldNotAllocateMemory;

	return PTsshThread::init();
}

///////////////////////////////////////////////////////////////////////////////
int32 
SftpRequestMgr::createRequest(
		uint32 &requestID,
		pthread_cond_t **ppCondVar,
		pthread_mutex_t **ppMutex)
{
	int32 result = PTSSH_ERR_CouldNotAllocateMemory;
	uint32
		i = 0;

	//Create a new request node
	RequestNode *pRN = new RequestNode();
	while(1)
	{
		if ( ! pRN)
			break;

		if (pthread_cond_init(  &pRN->condVar, 0) != 0)
			break;
		if (pthread_mutex_init( &pRN->mutex, 0) != 0)
			break;
		result = pRN->dataQ.init();

		pthread_mutex_lock( &m_requestIdMutex);
			pRN->requestID = m_requestID++;
			requestID = pRN->requestID;
			//PTLOG((LL_debug3, "Created request %d\n", requestID));
		pthread_mutex_unlock( &m_requestIdMutex);

		//Add the new node to the list
		pthread_mutex_lock( &m_reqListMutex);
			result = m_pReqList->insertAtEnd( pRN);;
		pthread_mutex_unlock( &m_reqListMutex);
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32 
SftpRequestMgr::deleteRequest(uint32 requestID)
{
	RequestNode 
		*pRN = NULL;
	int32 
		result = findRequestNode(requestID, &pRN);
	if ( pRN) 
	{
		pthread_mutex_unlock( &pRN->mutex);
		pthread_cond_destroy(  &pRN->condVar);
		pthread_mutex_destroy( &pRN->mutex);
		delete pRN;
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32 
SftpRequestMgr::getRequestData(uint32 requestID, BinaryPacket **pBP)
{
	RequestNode 
		*pRN = NULL;
	int32 
		result = findRequestNode(requestID, &pRN);
	
	if ( pRN) 
	{
		*pBP = (BinaryPacket*)pRN->dataQ.dequeue();
		if ( *pBP)
			result = PTSSH_SUCCESS;
		else
			result = PTSSH_ERR_NoDataAvailable;
		pthread_mutex_unlock( &pRN->mutex);
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
void 
SftpRequestMgr::run()
{
	int32 result;

	if ( ! m_pChannelMgr || m_cNum == PTSSH_BAD_CHANNEL_NUMBER)
		return;

	bool
		bKeepRunning = true;

	do{
		BinaryPacket *pBP = NULL;
		result = m_pChannelMgr->getInboundData(
			m_cNum,
			&pBP,
			true,
			500,
			false);

		if ( result == PTSSH_SUCCESS)
		{
			uint32 
				i = 0,
				packetRequestID = pBP->sftpRequestID();
			uint8 
				*pSftpData = pBP->sftpData();
			bool
				bIsSftpDataPacket = *pSftpData == SSH_FXP_DATA;
			RequestNode 
				*pRN = NULL;

			//PTLOG((LL_debug3, "SftpRequestMgr got data for request %d\n", packetRequestID));
	
			/* Find the correct request item in our array, add the 
			data to it and alert any interested thread. */
			findRequestNode(packetRequestID, &pRN);

			if ( pRN)
			{
				pRN->dataQ.enqueue( pBP);

				/* IF we get a data packet, we need to read out the length and then
				 * listen until we recieve all of the packet's data. A Sftp data
				 * packet will quite often span multiple packets */
				if ( bIsSftpDataPacket)
				{
					uint32 
						sftpBytesRead = 0,
						totalSftpBytesToRead;
					pSftpData += 5;

					//This is the total number of bytes that will be sent over
					totalSftpBytesToRead = PTSSH_htons32( (uint32*)pSftpData);

					//Get the length of bytes in this packet
					sftpBytesRead = pBP->getChannelDataLen() - 13;

					//Done with BP
					pBP = NULL;

					//Wait for the rest of the request to come in, or an error to occur
					result = waitForRequestData(pRN, totalSftpBytesToRead, sftpBytesRead);
				}

				//Mutex is already locked
				//PTLOG(( LL_debug3, "Got data for a request %d\n", pRN->requestID));
				pthread_cond_signal( &pRN->condVar);    //Alert anyone waiting
				pthread_mutex_unlock( &pRN->mutex);
			}
			else
			{
				//Request Item could not be found!!!
				PTLOG(( LL_error, "Error: Got data for a request that we were not ready for!\n"));
			}
		}
		
		pthread_mutex_lock( &m_isRunningMutex);
			bKeepRunning = ! m_bStopRunning;
		pthread_mutex_unlock( &m_isRunningMutex);
	} while (bKeepRunning);
}

///////////////////////////////////////////////////////////////////////////////
int32 
SftpRequestMgr::waitForRequestData(RequestNode *pRN, uint32 &totalSftpBytesToRead, uint32 &sftpBytesRead)
{
	int32
		result = PTSSH_SUCCESS;
	bool
		bKeepWaiting = true;
	Queue
		*pQ = &pRN->dataQ;

	while ( bKeepWaiting && sftpBytesRead < totalSftpBytesToRead)
	{
		BinaryPacket 
			*pBP = NULL;
		result = m_pChannelMgr->getInboundData(
			m_cNum,
			&pBP,
			true,
			500,
			false);

		if ( pBP && result == PTSSH_SUCCESS)
		{
			//Get the length of bytes in this packet
			//PTLOG((LL_debug3, "SftpRequestMgr got data packet for request %d.\n", pRN->requestID));
			sftpBytesRead += pBP->getChannelDataLen();
			pQ->enqueue(pBP);
		}
		else if ( result != PTSSH_ERR_NoDataAvailable)
			bKeepWaiting = false;
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32 
SftpRequestMgr::findRequestNode(uint32 requestID, RequestNode **ppRN)
{
	RequestNode 
		*pRN = NULL;
	int32 
		result = PTSFTP_E_CouldNotFindMatchingRequestNode;
	
	*ppRN = NULL;

	pthread_mutex_lock( &m_reqListMutex);
	
	//Find the request node
	for(uint32 i=0; i < m_pReqList->size(); i++)
	{
		pRN = (RequestNode*)m_pReqList->peek(i);
		if ( pRN->requestID == requestID)  {
			*ppRN = pRN;
			break;
		}
	}

	if ( pRN) 
	{
		//Lock access to this node
		pthread_mutex_lock( &pRN->mutex);
		result = PTSSH_SUCCESS;
	}

	pthread_mutex_unlock( &m_reqListMutex);
	return result;
}

#endif

