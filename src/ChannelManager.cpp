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
#include "ChannelManager.h"
#include "Channel.h"
#include "Queue.h"
#include "LinkedList.h"
#include "BinaryPacket.h"
#include "SSH2Types.h"
#include "PTsshLog.h"

#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif


#include <stdio.h>
#include <string.h>
#ifdef _DEBUG
#   include <assert.h>
#endif

/** For each channel, we allow up to 4 threads to do read-like operations. 
 * A read-like operation is any operating that does not delete or modify
 * the pointer to the Channel object. In order to destroy a Channel
 * a process must acquire all read locks to assure that no threads are 
 * waiting on a signal inside the Channel class or are otherwise in a
 * state where deleting the channel object would cause a crash 
 */
#define MaxReadThreadsPerChannel 4

///////////////////////////////////////////////////////////////////////////////
ChannelManager::ChannelManager(void):
m_pMainQ(0),
m_pQueueList(0)
{
	//Init the channel pointer array
	for (int i = 0; i < PTSSH_MAX_CHANNELS; i++)
	{
		m_pChannel[i] = NULL;
	}
}

///////////////////////////////////////////////////////////////////////////////
ChannelManager::~ChannelManager(void)
{
	pthread_mutex_destroy( &m_generalMutex);
	
	if ( m_pMainQ)
	{
		//Remove the node from the queue list if its in there
		if ( m_pQueueList)
			m_pQueueList->removeNodeWithMatchingData( m_pMainQ);

		delete m_pMainQ;
		m_pMainQ = NULL;
	}

	//Destroy all channels
	for (int i = 0; i < PTSSH_MAX_CHANNELS; i++)
	{
		if ( m_pChannel[i])
		{
			//Remove the node from the queue list if its in there
			if ( m_pQueueList)
				m_pQueueList->removeNodeWithMatchingData( m_pChannel[i]);

			delete m_pChannel[i];
			m_pChannel[i] = NULL;
		}
	}

	if ( m_pQueueList)
	{
		//Remove any Queues left in the list
		while ( m_pQueueList->size() > 0)
		{
			Queue *pQ = (Queue*)m_pQueueList->removeFirst();
			if ( pQ)
				delete pQ;
		}

		delete m_pQueueList;
		m_pQueueList = NULL;
	}
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::init()
{
	int32 result = PTSSH_SUCCESS;

	if ( pthread_mutex_init( &m_generalMutex, 0) != 0)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

	//Make a new global queue to hold all non-channel data related packets
	m_pMainQ = new Queue();
	if ( ! m_pMainQ)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

	if ( m_pMainQ->init() != PTSSH_SUCCESS)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

	//Create our linked list that we will use to quickly iterate over the queues
	m_pQueueList = new LinkedList();
	if ( ! m_pQueueList)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

	/* Add the new channel's queue to our linked list so that we will cycle through
	 * it when looking for packets to send */
	if ( ! m_pQueueList->insertAtEnd( m_pMainQ ))
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}


	return result;

error:
	pthread_mutex_destroy( &m_generalMutex);

	if ( m_pMainQ)
	{
		delete m_pMainQ;
		m_pMainQ = NULL;
	}

	if ( m_pQueueList)
	{
		delete m_pQueueList;
		m_pQueueList = NULL;
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::newChannel(uint32 windowSize, uint32 maxPacketSize, PTsshChannelType channelType, uint32 &channelNum)
{
	uint32 
		i = 0,
		result = PTSSH_SUCCESS;

	pthread_mutex_lock( &m_generalMutex);

		//Find the next available open spot
		for ( ; i < PTSSH_MAX_CHANNELS; i++)
		{
			if ( ! m_pChannel[i])
				break;
		}

		if ( i == PTSSH_MAX_CHANNELS)
		{
			//No channels are available
			result = PTSSH_ERR_MaxChannelsReached;
			goto error;
		}

		//Create the channel object
		m_pChannel[i] = new Channel( windowSize, channelType);
		if ( ! m_pChannel[i])
		{
			result = PTSSH_ERR_CouldNotAllocateMemory;
			goto error;
		}
		if ( ! m_pChannel[i]->init(i) )
		{
			result = PTSSH_ERR_CouldNotInitializeChannelObject;
			goto error;
		}

		//Set some channel-specific data depending on the type of channel
		switch (channelType){
			case PTsshCT_forwarded_tcpip:
				/* For remote port forwarding, we create a placeholder channel so that when the server
				* later tries to open a channel and claims that its because of a port forward, we can
				* verify that is true. We then spin off an active channel to handle the new tunnel 
				* Since this is our placeholder-verify channel, mark it as having already sent
				* and received a close message so that we never try and send a close message on this
				* channel when cleaning up */
				m_pChannel[i]->m_bChannelCloseSent = true;
				m_pChannel[i]->m_bChannelCloseRecvd = true;
				m_pChannel[i]->m_bForwardPlaceholder = true;
				break;
		}

		/* Add the new channel's queue to our linked list so that we will cycle through
		 * it when looking for packets to send */
		if ( ! m_pQueueList->insertAtEnd( m_pChannel[i]->m_pOutboundQueue ))
		{
			result = PTSSH_ERR_CouldNotAllocateMemory;
			goto error;
		}

		//Channel created successfuly, set the index so the calling process can reference this object
		channelNum = i;

	pthread_mutex_unlock( &m_generalMutex);
	return result;

error:
	//Cleanup and return error
	if ( m_pChannel[i])
	{
		delete m_pChannel[i];
		m_pChannel[i] = NULL;
	}

	pthread_mutex_unlock( &m_generalMutex);
	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32 
ChannelManager::deleteChannel( uint32 cNum, bool bSendCloseMsg)
{
	int32 
		result = PTSSH_SUCCESS;

	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		//Channel is valid, have we already send a channel close message?
		pthread_mutex_lock( &pChannel->m_channelCloseMutex);
		if ( ! pChannel->m_bChannelCloseRecvd && bSendCloseMsg)
		{
			//Have not reveived a channel close message
			if ( ! pChannel->m_bChannelCloseSent)
			{
				//We have not sent a channel close message, send one now
				uint32 len = 1 + 4;
				BinaryPacket *pBP = new BinaryPacket(cNum);
				if (pBP && pBP->init(len) )
				{
					pBP->writeByte( SSH_MSG_CHANNEL_CLOSE);
					pBP->writeUint32( pChannel->m_channelNumberRemote );
					
					result = pChannel->m_pOutboundQueue->enqueue(pBP);
					if ( result != PTSSH_SUCCESS)
						delete pBP;
				}
				else
					return PTSSH_ERR_CouldNotAllocateMemory;

				pChannel->m_bChannelCloseSent = true;
			}

			//Wait for a channel close message or error
			pthread_cond_wait( &pChannel->m_channelClose_cv, &pChannel->m_channelCloseMutex);

			/* When we here, we will have received a channel close message. Unfortunately, I'm
			 * also counting that the remote end will not send this channel any messages while
			 * we shut it down and delete it. As per the SSH spec, it's not allowed... 
			 * So SocketRecieve through Transport will not enqueue any packets to this
			 * channel's queues.*/
		}

		/* We have recieved a channel close, Remove this channel's queue from the m_pQueueList.
		 * We don't want SocketSend trying to query this channel's queue if its going to be
		 * deleted */
		pthread_mutex_lock( &m_generalMutex);
			m_pQueueList->removeNodeWithMatchingData( pChannel->m_pOutboundQueue);
		pthread_mutex_unlock( &m_generalMutex);

		/* At this point, they only thread that could access this channel would be if the
		 * end-developer had another thread making a call into PTssh.cpp dealing with this
		 * channel. Which could happen... */
		pthread_mutex_unlock( &pChannel->m_channelCloseMutex);

		delete m_pChannel[cNum];
		m_pChannel[cNum] = NULL;
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32 
ChannelManager::getChannelCreateResult(uint32 cNum)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_requestResultMutex);
		while ( pChannel->m_channelStatus == Channel::CS_unknown)
		{
			//Channel has not yet recieved any info about its status, block and wait for status
			pthread_cond_wait( 
				&pChannel->m_requestResult_cv, 
				&pChannel->m_requestResultMutex);
		}

		if ( pChannel->m_channelStatus != Channel::CS_open)
			result = PTSSH_ERR_ChannelRequestFailed;

		pthread_mutex_unlock( &pChannel->m_requestResultMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32 
ChannelManager::setChannelCreateResult(uint32 cNum, bool bResult)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		if ( pChannel)
		{
			pthread_mutex_lock( &pChannel->m_requestResultMutex);
				if ( bResult)
					pChannel->m_channelStatus = Channel::CS_open;
				else
					pChannel->m_channelStatus = Channel::CS_failedToCreate;

				//Now signal any process that might be waiting on getChannelCreateResult() that it has an answer
				pthread_cond_signal( &pChannel->m_requestResult_cv );
			pthread_mutex_unlock( &pChannel->m_requestResultMutex);
		}
		else
			result = PTSSH_ERR_InvalidChannelNumber;
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32 
ChannelManager::getChannelRequestResult(uint32 cNum)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_requestResultMutex);
			if ( pChannel->m_requestResult == Channel::CRR_pending)
			{
				pthread_cond_wait(
					&pChannel->m_requestResult_cv,
					&pChannel->m_requestResultMutex);
			}

			if ( pChannel->m_requestResult != Channel::CRR_success)
				result = PTSSH_ERR_ChannelRequestFailed;

			//reset the variable for the next request
			pChannel->m_requestResult = Channel::CRR_pending;
		pthread_mutex_unlock( &pChannel->m_requestResultMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32 
ChannelManager::setChannelRequestResult(uint32 cNum, bool bResult)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_requestResultMutex);
			if ( bResult)
				pChannel->m_requestResult = Channel::CRR_success;
			else
				pChannel->m_requestResult = Channel::CRR_failure;

			//Tell the any process waiting on the result that we got a response
			pthread_cond_signal( &pChannel->m_requestResult_cv);
		pthread_mutex_unlock( &pChannel->m_requestResultMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
bool 
ChannelManager::isValidChannelNumber( uint32 cNum)
{
	return cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum];
}

///////////////////////////////////////////////////////////////////////////////
bool 
ChannelManager::isValidRemotePortForward(const char *pHostAddr, uint16 port)
{
	bool bMatch = false;
	pthread_mutex_lock( &m_generalMutex);
	for (uint32 cNum = 0; cNum < PTSSH_MAX_CHANNELS; cNum++)
	{
		Channel *pChannel = m_pChannel[cNum];
		if ( pChannel->m_channelType == PTsshCT_forwarded_tcpip
			&& pChannel->m_bForwardPlaceholder)
		{
			//Check for matching address and port
			if ( strcmp( pChannel->m_pForwardIPAddr, pHostAddr) == 0
				&& pChannel->m_forwardPort == port)
			{
				bMatch = true;
				break;
			}
		}
	}

	pthread_mutex_unlock( &m_generalMutex);

	return bMatch;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::getInboundData(uint32 cNum, BinaryPacket **ppBuf, bool bIsBlockingRead, uint32 microsecTimeout, bool bExtendedData)
{
	*ppBuf = NULL;
	int32 
		result = PTSSH_SUCCESS;
	struct timespec 
		timeoutTime;

	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		if ( bExtendedData)
		{
			pthread_mutex_lock( &pChannel->m_activityStdErrorMutex);
				*ppBuf = pChannel->m_pInboundStdErrorQueue->dequeue();
				if ( *ppBuf == NULL && bIsBlockingRead)
				{
					if ( microsecTimeout > 0)
					{
						getAbsoluteTime(microsecTimeout, timeoutTime);

						pthread_cond_timedwait(
							&pChannel->m_activityStdError_cv,
							&pChannel->m_activityStdErrorMutex,
							&timeoutTime);
					}
					else
					{
						pthread_cond_wait( 
							&pChannel->m_activityStdError_cv,
							&pChannel->m_activityStdErrorMutex);
					}

					*ppBuf = pChannel->m_pInboundStdErrorQueue->dequeue();
					if ( *ppBuf == NULL)
					{
						/* This shouldn't happen unless the socket died while we were blocking
						 * or the user blocked only for a set amount of time and no data arrived
						 * during that time */
						result = PTSSH_ERR_NoDataAvailable;
					}
				}
			pthread_mutex_unlock( &pChannel->m_activityStdErrorMutex);
		}
		else
		{
			uint32 
				windowSizeToAdd = 0;
			
			pthread_mutex_lock( &pChannel->m_activityDataMutex);
				*ppBuf = pChannel->m_pInboundDataQueue->dequeue();
				if ( *ppBuf == NULL && bIsBlockingRead)
				{
					if ( microsecTimeout > 0)
					{
						getAbsoluteTime(microsecTimeout, timeoutTime);
						
						pthread_cond_timedwait(
							&pChannel->m_activityData_cv,
							&pChannel->m_activityDataMutex,
							&timeoutTime);
					}
					else
					{
						//PTLOG((LL_debug3, "[ChannelMgr] Thread waiting for data on channel %d...\n", cNum));
						pthread_cond_wait( 
							&pChannel->m_activityData_cv, 
							&pChannel->m_activityDataMutex);
					}

					//PTLOG(("[ChannelMgr] Thread waiting for data on channel %d has been woken up!\n", cNum));
					*ppBuf = pChannel->m_pInboundDataQueue->dequeue();
					if ( *ppBuf == NULL)
					{
						//This shouldn't happen unless the socket died while we were blocking
						result = PTSSH_ERR_NoDataAvailable;
					}
				}

				/* Check to see if we should add more window space. The window space
				 * is based on the amount of room left in our queue */
				windowSizeToAdd = PTSSH_MAX_OUTBOUND_QUEUE_SIZE - pChannel->m_windowSizeLocal;

			pthread_mutex_unlock( &pChannel->m_activityDataMutex);

			//If the window size to add is 1/32 of the max queue size or greater, send an adjust msg
			if ( windowSizeToAdd >= (PTSSH_MAX_OUTBOUND_QUEUE_SIZE >> 5))
			{
				uint32
					remoteChannelNum,
					len =
						1 + //byte      SSH_MSG_CHANNEL_WINDOW_ADJUST
						4 + //uint32    recipient channel
						4;  //uint32    bytes to add
				//PTLOG(("[CM] Sending window adjust %d bytes\n", windowSizeToAdd));
				getRemoteChannelNumber(cNum, remoteChannelNum);
				BinaryPacket *pBP = new BinaryPacket(cNum);
				if (  pBP && pBP->init( len) )
				{
					pBP->writeByte(SSH_MSG_CHANNEL_WINDOW_ADJUST);
					pBP->writeUint32( remoteChannelNum);
					pBP->writeUint32( windowSizeToAdd);

					result =pChannel->m_pOutboundQueue->enqueue( pBP);
					if ( result == PTSSH_SUCCESS)
						pChannel->m_windowSizeLocal += windowSizeToAdd;
					else
						delete pBP;

					pBP = NULL;
				}

				/* We only run this if we failed. But this isn't 
				 * critical, we will retry on next channel read */
				if ( pBP)
				{
					delete pBP;
					pBP = NULL;
				}
			}
		}
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::queueInboundData(uint32 cNum, BinaryPacket *pBuf, bool bExtendedData)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		if ( bExtendedData)
		{
			pthread_mutex_lock( &pChannel->m_activityStdErrorMutex);
				if ( pChannel->m_pInboundStdErrorQueue->enqueue( pBuf) == PTSSH_SUCCESS )
				{
					PTLOG((LL_debug2, "[ChannelMgr] SIGNALING e-data: Added extended data packet to channel %d\n", cNum));
					pthread_cond_signal( &pChannel->m_activityStdError_cv);
				}
				else
					result = PTSSH_ERR_CouldNotQueuePacketForRecieving;
			pthread_mutex_unlock( &pChannel->m_activityStdErrorMutex);
		}
		else
		{
			pthread_mutex_lock( &pChannel->m_activityDataMutex);
				//Adjust the size of the window
				uint32
					dataSize = pBuf->getChannelDataLen();

				pChannel->m_windowSizeLocal -= dataSize;

				if ( pChannel->m_pInboundDataQueue->enqueue( pBuf) == PTSSH_SUCCESS)
				{
					//PTLOG(("[ChannelMgr] SIGNALING Data: Added packet to channel %d\n", cNum));
					pthread_cond_signal( &pChannel->m_activityData_cv);
				}
				else
					result = PTSSH_ERR_CouldNotQueuePacketForRecieving;
			pthread_mutex_unlock( &pChannel->m_activityDataMutex);
		}
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::queueOutboundData(BinaryPacket *pBP)
{
	int32 result = PTSSH_SUCCESS;
	bool bGoesInChannelQueue = false;

	//Open up the packet and see which queue we should place it in
	switch ( pBP->getSSHMessageType())
	{
		//case SSH_MSG_CHANNEL_OPEN:
		case SSH_MSG_CHANNEL_WINDOW_ADJUST:
		case SSH_MSG_CHANNEL_DATA:
		case SSH_MSG_CHANNEL_EXTENDED_DATA:
		case SSH_MSG_CHANNEL_EOF:
		case SSH_MSG_CHANNEL_CLOSE:
		case SSH_MSG_CHANNEL_REQUEST:
			bGoesInChannelQueue = true;

		//All other SSH packet types go into the mainQ
	}

	if ( bGoesInChannelQueue)
	{
		uint32 cNum = pBP->getChannelNum();
		if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
		{
			Channel *pChannel = m_pChannel[cNum];
			uint32 bytesAllowed;
			
			pthread_mutex_lock(&pChannel->m_outboundQMutex );
			while (pBP)
			{
				//Get the number of bytes we can place in the queue
				bytesAllowed = PTSSH_MAX_OUTBOUND_QUEUE_SIZE - pChannel->m_pOutboundQueue->m_totalBytesInQ;

				//Will we be under our limit if we place this packet in the queue?
				if (pBP->getTotalPacketLength() <= bytesAllowed)
				{
					//Also if this packet is a channel close, set the appropriate flags
					if (pBP->getSSHMessageType() == SSH_MSG_CHANNEL_CLOSE)
					{
						pthread_mutex_lock( &pChannel->m_channelCloseMutex);
							pChannel->m_bChannelCloseSent = true;
						pthread_mutex_unlock( &pChannel->m_channelCloseMutex);
					}

					//Queue the packet so it'll be sent soonish
					result = pChannel->m_pOutboundQueue->enqueue( pBP);
					if (result != PTSSH_SUCCESS)
						delete pBP;
					pBP = NULL;

					pthread_mutex_unlock(&pChannel->m_outboundQMutex );
				}
				else
				{
					/* We can't yet put this packet in the queue, we are over our limit
					 * wait until we send pull some data out of the queue and then
					 * try again */
					pthread_cond_wait( &pChannel->m_outboundQ_cv, &pChannel->m_outboundQMutex);
				}
			}
		}
		else
		{
#ifdef _DEBUG
			PTLOG((LL_error, "[CM] Tried to queue a packet on an invalid channel number\n"));
#endif
			result = PTSSH_ERR_InvalidChannelNumber;
		}
	}
	else
		result = m_pMainQ->enqueue( pBP);

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::adjustWindowSizeRemote(uint32 cNum, int32 bytesToAddOn)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_generalMutex);

#ifdef _DEBUG
			if ( bytesToAddOn < 0)
			{
				if ( ((uint32)(-1 * bytesToAddOn)) > pChannel->m_windowSizeRemote)
				{
					PTLOG((LL_error, "oops\n"));
				}
			}
#endif

			pChannel->m_windowSizeRemote += bytesToAddOn;

			//ptLog("[SR] Window size is %dKB, was adjusted by %dKB\n", 
			//	(pChannel->m_windowSizeRemote >> 10),
			//	(bytesToAddOn >> 10));
			/* Set the safe to send flag. IF SS is waiting for window space,
			 * setting this flag will let it know that it can send on this channel */
			pChannel->m_bSafeToSend = true;
		pthread_mutex_unlock( &pChannel->m_generalMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32 
ChannelManager::setInitialRemoteWindowSize(uint32 cNum, uint32 size)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_generalMutex);
			pChannel->m_windowSizeRemote = size;
		pthread_mutex_unlock( &pChannel->m_generalMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::adjustWindowSizeLocal(uint32 cNum, int32 bytesToAddOn)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_generalMutex);
			pChannel->m_windowSizeLocal += bytesToAddOn;
		pthread_mutex_unlock( &pChannel->m_generalMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::getMaxPacketSizeRemote(uint32 cNum, uint32 &size)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_generalMutex);
			size = pChannel->m_maxPacketSizeRemote;
		pthread_mutex_unlock( &pChannel->m_generalMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::setMaxPacketSizeRemote(uint32 cNum, uint32 size)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_generalMutex);
			pChannel->m_maxPacketSizeRemote = size;
		pthread_mutex_unlock( &pChannel->m_generalMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::getEOF(uint32 cNum, bool &bResult)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_EOFMutex );
			bResult = pChannel->m_bEOFRecieved;
		pthread_mutex_unlock( &pChannel->m_EOFMutex );
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::waitForEOF(uint32 cNum)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_EOFMutex );
		if ( ! pChannel->m_bEOFRecieved)
		{
			//Blocking wait until we get a signal to continue
			pthread_cond_wait(
				&pChannel->m_EOF_cv,
				&pChannel->m_EOFMutex);

			//If we were signaled and we did;t recieve the EOF, some other error must have occured
			if ( ! pChannel->m_bEOFRecieved)
				result = PTSSH_FAILURE;
		}
		pthread_mutex_unlock( &pChannel->m_EOFMutex );
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::setEOF_recieved(uint32 cNum)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_EOFMutex );
			pChannel->m_bEOFRecieved = true;
				//signal any thread blocking on EOF that we recieved it!
			pthread_cond_signal( &pChannel->m_EOF_cv);
		pthread_mutex_unlock( &pChannel->m_EOFMutex );
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::isOpen(uint32 cNum, bool &bResult)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_channelCloseMutex);
			if ( pChannel->m_channelStatus == Channel::CS_open)
				bResult = true;
			else
				bResult = false;
		pthread_mutex_unlock( &pChannel->m_channelCloseMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::bAlreadySentCloseMsg(uint32 cNum, bool &bResult)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_channelCloseMutex);
			bResult = pChannel->m_bChannelCloseSent;
		pthread_mutex_unlock( &pChannel->m_channelCloseMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::waitForChannelClose(uint32 cNum)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_channelCloseMutex);
		if ( ! (pChannel->m_channelStatus == Channel::CS_closed) )
		{
			pthread_cond_wait(
				&pChannel->m_channelClose_cv,
				&pChannel->m_channelCloseMutex);

			/* If we were signaled and we did;t recieve the channel close message,
			 * some other error must have occured. Return general failure */
			if ( ! (pChannel->m_channelStatus == Channel::CS_closed) )
				result = PTSSH_FAILURE;
		}
		pthread_mutex_unlock( &pChannel->m_channelCloseMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::getRemoteChannelNumber(uint32 localChannelNumber, uint32 &remoteChannelNum)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( localChannelNumber < PTSSH_MAX_CHANNELS && m_pChannel[localChannelNumber] )
	{
		Channel *pChannel = m_pChannel[localChannelNumber];
		pthread_mutex_lock( &pChannel->m_generalMutex);
			remoteChannelNum = m_pChannel[localChannelNumber]->m_channelNumberRemote;
		pthread_mutex_unlock( &pChannel->m_generalMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::setRemoteChannelNumber(uint32 localChannelNumber, uint32 remoteChannelNum)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( localChannelNumber < PTSSH_MAX_CHANNELS && m_pChannel[localChannelNumber] )
	{
		Channel *pChannel = m_pChannel[localChannelNumber];
		pthread_mutex_lock( &pChannel->m_generalMutex);
			pChannel->m_channelNumberRemote = remoteChannelNum;
		pthread_mutex_unlock( &pChannel->m_generalMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::setChannelCloseMsgReceived(uint32 cNum)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		//Channel is valid, have we already send a channel close message?
		pthread_mutex_lock( &pChannel->m_channelCloseMutex);
			pChannel->m_bChannelCloseRecvd = true;
			pChannel->m_channelStatus = Channel::CS_closed;

			//Signal any process waiting on the close message
			pthread_cond_signal( &pChannel->m_channelClose_cv);

		pthread_mutex_unlock( &pChannel->m_channelCloseMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::setForwardedTcpIpData( uint32 cNum, const char *IPAddr, uint16 port)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_generalMutex);
		
			pChannel->m_pForwardIPAddr = strdup(IPAddr);
			if ( pChannel->m_pForwardIPAddr)
			{
				pChannel->m_forwardPort = port;
			}
			else
				result = PTSSH_ERR_CouldNotAllocateMemory;

		pthread_mutex_unlock( &pChannel->m_generalMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::setForwardNotifierCallbackData(uint32 cNum, struct PTsshCallBackData *pForwardData)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		pthread_mutex_lock( &m_pChannel[cNum]->m_generalMutex);
			m_pChannel[cNum]->m_pCallbackData = pForwardData;
		pthread_mutex_unlock( &m_pChannel[cNum]->m_generalMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::getForwardNotifierCallbackData(const char *IPAddr, uint16 port, struct PTsshCallBackData **ppForwardData)
{
	bool bMatch = false;
	int32 result;
	Channel *pChannel = NULL;
	*ppForwardData = NULL;

	pthread_mutex_lock( &m_generalMutex);
	for (uint32 cNum = 0; cNum < PTSSH_MAX_CHANNELS; cNum++)
	{
		pChannel = m_pChannel[cNum];
		if ( pChannel->m_channelType == PTsshCT_forwarded_tcpip
			&& pChannel->m_bForwardPlaceholder)
		{
			//Check for matching address and port
			if ( strcmp( pChannel->m_pForwardIPAddr, IPAddr) == 0
				&& pChannel->m_forwardPort == port)
			{
				bMatch = true;
				break;
			}
		}
	}

	if (bMatch)
	{
		*ppForwardData = new struct PTsshCallBackData(NULL);
		memcpy( *ppForwardData, pChannel->m_pCallbackData, sizeof(struct PTsshCallBackData));
		result = PTSSH_SUCCESS;
	}
	else
		result = PTSSH_ERR_CallbackDataNotFound;

	pthread_mutex_unlock( &m_generalMutex);

	return result;
}
	
///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::getForwardedTcpIpData( uint32 cNum, char **ppIPAddr, uint16 &port)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_generalMutex);
			*ppIPAddr = strdup( pChannel->m_pForwardIPAddr);
			if ( *ppIPAddr)
			{
				port = pChannel->m_forwardPort;
			}
			else
				result = PTSSH_ERR_CouldNotAllocateMemory;

		pthread_mutex_unlock( &pChannel->m_generalMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::setX11ForwardStatus( uint32 cNum, bool bIsEnabled)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_generalMutex);
			pChannel->m_bX11Forwarding = bIsEnabled;
		pthread_mutex_unlock( &pChannel->m_generalMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::getX11ForwardStatus( uint32 cNum, bool &bIsEnabled)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( cNum < PTSSH_MAX_CHANNELS && m_pChannel[cNum] )
	{
		Channel *pChannel = m_pChannel[cNum];
		pthread_mutex_lock( &pChannel->m_generalMutex);
			bIsEnabled = pChannel->m_bX11Forwarding;
		pthread_mutex_unlock( &pChannel->m_generalMutex);
	}
	else
		result = PTSSH_ERR_InvalidChannelNumber;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
ChannelManager::getNextPacket(bool bIsInKeyXMode, uint32 maxTotalSize,	BinaryPacket **ppBP)
{
	int32 
		result = PTSSH_SUCCESS;
	
	//Make sure its empty
	*ppBP = NULL;

	Queue 
		*pQueue = NULL;

	if ( bIsInKeyXMode)
	{
		//No need to lock, PTsshQueues are thread-safe
		for (uint32 i = 0; i < m_pMainQ->size(); i++)
		{
			uint8 msgType;
			*ppBP = m_pMainQ->peek( i);
			if ( *ppBP)
			{
				msgType = (*ppBP)->getSSHMessageType();
				//Make sure the packet is a keyX type
				if (msgType == SSH_MSG_KEXINIT || msgType == SSH_MSG_KEXDH_INIT || msgType == SSH_MSG_NEWKEYS)
				{
					//make sure we have enough room
					if ( (*ppBP)->getTotalPacketLength() <= maxTotalSize)
					{
						*ppBP = m_pMainQ->remove(i);
						break;
					}
				}
				else
					*ppBP = NULL;
			}
		}
	}
	else
	{
		pthread_mutex_lock( &m_generalMutex);

		//Get the next queue to work on that has packets to be sent
		if ( m_pQueueList && m_pQueueList->size() )
		{
			bool
				bKeepGoing = true,
				bFirstRound = true;

			while ( bKeepGoing)
			{
				LinkedList::Node *pNode = m_pQueueList->getNextNode();
				if (pNode)
				{
					pQueue = (Queue*)pNode->m_pData;
				}
				else //We hit the end of our queue list
				{
					if ( bFirstRound)
					{
						bFirstRound = false;
					}
					else
					{
						/* This is the 2nd time we hit the end of the list. This means we have
						 * gone through all of the queues and not found any data to send.
						 * Bomb out, we don't have any packets that we can send at this time */
						bKeepGoing = false;
					}
				}

				//If this queue doesn't have any packets, skip it
				if ( pQueue && pQueue->size())
				{
					*ppBP = pQueue->peek();

					//If its a channel data queue, make sure we have window space
					if ( pQueue->m_bLinkedToCNum)
					{
						/* Ok, we have a channel data queue. This queue holds channel related
						 * data packets. */
						if ( (*ppBP)->getSSHMessageType() == SSH_MSG_CHANNEL_DATA)
						{
							/* We are looking at a channel data packet. Take window size into account
							 * along with total packet size */
							bool 
								bResult = false;
							Channel
								*pChannel = m_pChannel[(*ppBP)->getChannelNum()];
							uint32 
								cNum = (*ppBP)->getChannelNum(),
								remoteWinSpace = pChannel->m_windowSizeRemote,		  // In # of channelData bytes
								remoteMaxPacketSize = pChannel->m_maxPacketSizeRemote,// In # of channelData bytes
								channelDataSize = (*ppBP)->getChannelDataLen(),               // In # of channelData bytes
								maxChannelDataInPacket;
							/* Calculate the blockSize adjustment. This amount of bytes needs to be subtracted
							 * when we calculate the amount of channel data we can fit in the packet so that
							 * the packet size will be an evenly divisible blocksize */
							uint8
								blockSizeAdj = (maxTotalSize % 16);

							/*Lets adjust the maxChannelDataInPacket to account for overhead and padding
							 packet_length + padding_length + channelDataByte + 
							 channelNum + dataLen + 4byteMinPadding + blockSizeAdj
							 */
							maxChannelDataInPacket = maxTotalSize - ((4 + 1 + 1 + 4 + 4 + 4) + blockSizeAdj);
							//Now adjust for minimum of 4 byte padding


							/* If there is window space and we can send at least 16 bytes of channel data.
							 * BinaryPacket layout for a SSH_MSG_CHANNEL_DATA
							 * 4 uint32    packet_length
							 * 1 byte      padding_length
							 * bytes[n1]  payload; n1 = packet_length - padding_length - 1
							 * {
							 *    1 byte      SSH_MSG_CHANNEL_DATA
							 *    4 uint32    recipient channel
							 *    4 + bufferSize ;//SSH string
							 * }
							 * So to send at least 16 bytes of channel data we'd need a total size of at least
							 *  32 bytes = 4 + 1 + 1 + 4 + 4 + 16 + (padding size of 2 bytes)
							 **/
							if ( remoteWinSpace > 16 && maxTotalSize >= 32)
							{
								/* Figure out how much channelData we can send with the remaining
								 * windowSpace and remaining writeBuffer space. Initially, set it to
								 * our packet's channel data size
								 */
								uint32
									maxChannelDataBytesWeCanSend = channelDataSize;

								//Adjust if window space remaining is smaller than the data length
								if ( remoteWinSpace < maxChannelDataBytesWeCanSend)
									maxChannelDataBytesWeCanSend = remoteWinSpace;
#ifdef _DEBUG
								assert( maxChannelDataBytesWeCanSend <= channelDataSize);
#endif
								//Adjust to smallest size based on maxPacketSize
								if ( remoteMaxPacketSize < maxChannelDataBytesWeCanSend)
									maxChannelDataBytesWeCanSend = remoteMaxPacketSize;

								if (maxChannelDataInPacket < maxChannelDataBytesWeCanSend)
									maxChannelDataBytesWeCanSend = maxChannelDataInPacket;

								/* Now the amount of data that we can send will be the smaller of:
									remoteWinSpace
									remoteMaxPacketSize
									maxTotalSize */

								//Do we need to split the packet?
								if ( maxChannelDataBytesWeCanSend < channelDataSize)
								{
									//ptLog("[CM] Splitting packet! channelDataSize %d, maxPacketSize %d, windowSpace %d, adjustedBufSpace %d\n",
									//	channelDataSize, remoteMaxPacketSize, remoteWinSpace, adjustedBufSpace);

									/* This removes the specified packet, splits it up and places the pieces
									 * back into the queue. The first packet at index "i" will fit perfectly
									 * into the remaining space in the buffer. */
									result = pQueue->splitFirstPacket(maxChannelDataBytesWeCanSend, remoteMaxPacketSize);
									if ( result != PTSSH_SUCCESS)
										break;
								}
								/* Else: The packet is small enough to be sent as-is. */

								*ppBP = pQueue->dequeue();
								if ( *ppBP)
								{
#ifdef _DEBUG
									uint32 totalLen = (*ppBP)->getTotalPacketLength();
									assert( totalLen <= maxTotalSize);
#endif
									/* Make sure our channelData size is correct. If this packet is the first
									* packet from a splitPacket() call, then our data size is wrong. */
									channelDataSize = (*ppBP)->getChannelDataLen();

									//Adjust the window, subtract the packet data size we are about to send
									adjustWindowSizeRemote( cNum, -1 * channelDataSize);

									//Take us out of the loop now that we have a packet
									bKeepGoing = false;
								}
							}
							else
							{
								/* We don't have enough window space or the space in the buffer is
								 * just not worth it. */
								*ppBP = NULL;
							}
						}
						else
						{
							/* We don't have channel data, therfore we can't split this packet.
							 * just make sure we have enough room to send the packet as-is */
							if ( (*ppBP)->getTotalPacketLength() <= maxTotalSize)
							{
								*ppBP = pQueue->dequeue();
								bKeepGoing = false;
							}
						}

						/* If we have a piece of channel data to send, signal any process that may
						 * be waiting to add data to this channel's inbound queue that it may be
						 * able to add it now that we have pulled a packet out of the queue */
						if ( *ppBP)
						{
							//Assuming all packets have the channel number field in the same spot!
							uint32 cNum = (*ppBP)->getChannelNum();
							pthread_mutex_lock( &m_pChannel[ cNum ]->m_outboundQMutex );
								pthread_cond_signal( &m_pChannel[ cNum ]->m_outboundQ_cv);
							pthread_mutex_unlock( &m_pChannel[ cNum ]->m_outboundQMutex );
						}
					}
					else
					{
						/* This is our global queue for all non-channel data, simply make sure
						 * theres enough room for this packet */
						//make sure we have enough room
						if ( (*ppBP)->getTotalPacketLength() <= maxTotalSize)
						{
							*ppBP = m_pMainQ->dequeue();
							bKeepGoing = false;
						}
					}
				}
			}

		}

		pthread_mutex_unlock( &m_generalMutex);
	}

	return result;
}
