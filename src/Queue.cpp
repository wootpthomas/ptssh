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
#include "PTsshConfig.h"
#include "Queue.h"
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


/*************************
 * Forward Declarations
 ************************/
//class BinaryPacket;



///////////////////////////////////////////////////////////////////////////////
Queue::Queue(uint32 cNum):
m_cNum(cNum),
m_totalBytesInQ(0)
{
	if ( m_cNum != 0xFFFFFFFF)
	{
		m_bLinkedToCNum = true;
	}
	else
	{
		m_bLinkedToCNum = false;
	}


}

///////////////////////////////////////////////////////////////////////////////
Queue::~Queue()
{
	//Delete any items in the queue
	while (m_size > 0)
	{
		BinaryPacket *ptr = this->dequeue();
		delete ptr;
	}

	pthread_mutex_destroy( &m_dataMutex);
}

///////////////////////////////////////////////////////////////////////////////
int32
Queue::init()
{
	if ( pthread_mutex_init( &m_dataMutex, 0) != 0)
		return PTSSH_ERR_CouldNotAllocateMemory;

	return PTSSH_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
int32
Queue::enqueue(BinaryPacket *pAddMe)
{
	struct Node *pNode = new Node(pAddMe);
	if ( pNode)
	{
		pthread_mutex_lock( &m_dataMutex);
			pTail->m_pNext = pNode;
			pTail = pNode;

			//Increment our counters
			++m_size;
			m_totalBytesInQ += pAddMe->getTotalPacketLength();
		pthread_mutex_unlock( &m_dataMutex);
		//PTLOG(("[PQ] Enqueued packet, Queue size: %d\n", m_size));
		return PTSSH_SUCCESS;
	}
	return PTSSH_ERR_CouldNotAllocateMemory;
}

///////////////////////////////////////////////////////////////////////////////
BinaryPacket *
Queue::dequeue(bool bIsMutexAlreadyLocked)
{
	BinaryPacket *pData = NULL;
	if ( ! bIsMutexAlreadyLocked)
		pthread_mutex_lock( &m_dataMutex);
	
	if ( m_size)
	{
		//Get pointer to first node in the list
		struct Node *pTemp = pHead->m_pNext;
		pData = (BinaryPacket *) pTemp->m_pData;

		//Re-route the node out of the list
		pHead->m_pNext = pHead->m_pNext->m_pNext;

		//Decrement our counters
		--m_size;
		m_totalBytesInQ -= pData->getTotalPacketLength();

		//Do we need to adjust the tail?
		if ( pTail == pTemp)
			pTail = pHead;

		delete pTemp;	//remove the node
	}

	if ( ! bIsMutexAlreadyLocked)
		pthread_mutex_unlock( &m_dataMutex);

	return pData;
}

/////////////////////////////////////////////////////////////////////////////////
BinaryPacket *
Queue::peek(uint32 index) 
{  
	BinaryPacket *pBP;
	pthread_mutex_lock( &m_dataMutex);
		pBP = (BinaryPacket*) LinkedList::peek(index); 
	pthread_mutex_unlock( &m_dataMutex);

	return pBP;
}

/////////////////////////////////////////////////////////////////////////////////
BinaryPacket *
Queue::remove(uint32 index)
{
	BinaryPacket *pBP;
	pthread_mutex_lock( &m_dataMutex);
		pBP = (BinaryPacket*) LinkedList::remove(index);
	pthread_mutex_unlock( &m_dataMutex);

	return pBP;
}

///////////////////////////////////////////////////////////////////////////////
int32
Queue::splitFirstPacket(uint32 firstSplitSize, uint32 Nth_splitSize)
{
	uint32
		dataLenLeft,
		bytesWritten = 0,
		remote_cNum,
		local_cNum,
		BPLen = 0,
		result = PTSSH_SUCCESS;

	struct Node 
		*pNewNode = NULL,
		*pNodeIter = NULL,
		*pNodeIterNext = NULL;

	//Don't let any other thread add/remove items while we are splitting
	pthread_mutex_lock( &m_dataMutex);

		//Remove the packet we are splitting from the queue
		BinaryPacket 
			*pBP_orig = dequeue(true),
			*pBP = NULL;

		uint8
			*pIter = pBP_orig->getPayloadPtr(),
			msgType = pBP_orig->getSSHMessageType();

		local_cNum = pBP_orig->getChannelNum();

		if ( msgType != SSH_MSG_CHANNEL_DATA)
		{
			result = PTSSH_ERR_TriedToSplitNonChannelDataPacket;
			goto exit;
		}

		PTLOG((LL_debug4, "[PQ] Splitting packet, channel data len %d bytes\n", pBP_orig->getChannelDataLen()));
		pIter++; //Move past the SSH_MSG_CHANNEL_DATA byte
		//Get the channel number
		remote_cNum = PTSSH_htons32( *((uint32*)pIter));
		pIter += 4;
		//Get the channel data length
		dataLenLeft = PTSSH_htons32( *((uint32*)pIter));
		pIter += 4;

		BPLen =
			1 +                  //byte      SSH_MSG_CHANNEL_DATA
			4 +                  //uint32    recipient channel
			4 + firstSplitSize;  //string    data

		pBP = new BinaryPacket(local_cNum);
		
		pNewNode = new Node(pBP);
		pNodeIter = pHead;
		pNodeIterNext = pHead->m_pNext;

		if ( pNewNode && pBP && pBP->init(BPLen))
		{
			//Fill the packet guts and copy in the data
			pBP->writeByte(SSH_MSG_CHANNEL_DATA);
			pBP->writeUint32(remote_cNum);

			//These next two essentially make up a SSH String type
			pBP->writeUint32(firstSplitSize );
			pBP->writeBytes( pIter, firstSplitSize);
			pIter += firstSplitSize;

			//Update the bytes left to be copied
			dataLenLeft -= firstSplitSize;
			
			//Put the new packet in place.
			pNodeIter->m_pNext = pNewNode;
			pNewNode->m_pNext = pNodeIterNext;

			//Increment our counters
			m_size++;
			m_totalBytesInQ += pBP->getTotalPacketLength();

			//Cleanup and get ready for next insertion
			pNodeIter = pNodeIter->m_pNext;
			if ( ! pNodeIterNext)  //Tail is effected
				pTail = pNewNode;

			pBP = NULL;
			pNewNode = NULL;
		}
		else
		{
			result = PTSSH_ERR_CouldNotAllocateMemory;
			goto exit;
		}

		//Now keep splitting the remaining data up into new binary packets
		//PTLOG(("[SS] Splitting first packet into %d bytes\n", firstSplitSize));
		while ( dataLenLeft > 0)
		{
			uint32 packetSize;
			if ( dataLenLeft < Nth_splitSize)
				packetSize = dataLenLeft;
			else
				packetSize = Nth_splitSize;

			//PTLOG(("[PQ] Splitting nth packet into %d bytes\n", packetSize));

			BPLen =
				1 +                  //byte      SSH_MSG_CHANNEL_DATA
				4 +                  //uint32    recipient channel
				4 + packetSize;     //string    data

			//Get the size of our next packet
			pBP = new BinaryPacket(local_cNum);
			pNewNode = new Node(pBP);
			if ( pNewNode && pBP && pBP->init( BPLen))
			{
				//Fill the packet guts and copy in the data
				pBP->writeByte(SSH_MSG_CHANNEL_DATA);
				pBP->writeUint32(remote_cNum);
				pBP->writeUint32(packetSize );
				pBP->writeBytes( pIter, packetSize);
				pIter += packetSize;

				//Update the bytes left to be copied
				dataLenLeft -= packetSize;
				
				//Put the new packet in place.
				pNodeIter->m_pNext = pNewNode;
				pNewNode->m_pNext = pNodeIterNext;

				//Increment our counters
				m_size++;
				m_totalBytesInQ += pBP->getTotalPacketLength();

				//Cleanup and get ready for next insertion
				pNodeIter = pNodeIter->m_pNext;
				if ( ! pNodeIterNext)  //Tail is effected
					pTail = pNewNode;

				pBP = NULL;
				pNewNode = NULL;
			}
			else
			{
				result = PTSSH_ERR_CouldNotAllocateMemory;
				goto exit;
			}
		}

exit:
	if ( pBP_orig)
		delete pBP_orig;
	if ( pBP)
		delete pBP;

	pthread_mutex_unlock( &m_dataMutex);
	return result;
}
