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

#ifndef _QUEUE
#define _QUEUE

/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"  //Used for dataTypes
#include "LinkedList.h"
#include <pthread.h>


/*************************
 * Forward Declarations
 ************************/
class BinaryPacket;


/**
* This class provides a quick implementation of a pointer-queue for 
* BinaryPackets.
* This class is implmented as a singly linked-list.
*/
class Queue:
	protected LinkedList
{
public:
	/**
	* Constructor. Specifies that this queue is associated with a channel number
	* We also set the default channel number to the maximum allowed size. this is
	* so that we can tell when this queue is not associated with a SSH channel
	*/
	Queue(uint32 cNum = 0xFFFFFFFF);
	
	~Queue();

	/**
	* Init's internal structures. 
	*/
	int32 init();

	/** THREAD SAFE
	* Returns the number of items in the list 
	*/
	uint32 size() { return LinkedList::size(); }

	/** THREAD SAFE
	* Enqueues a BinaryPacket
	*/
	int32 enqueue( BinaryPacket * pAdd);

	/** THREAD SAFE
	* Dequeues a BinaryPacket.
	*/
	BinaryPacket * dequeue()
	{   return dequeue(false); }

	/** THREAD SAFE to a degree....
	* Peeks at the first packet in the list. Remember the packet is still inside
	* the queue! This should not be a thread-safety concern because only SS
	* will peek at or remove items
	*/
	BinaryPacket * peek(uint32 index = 0);

	/** THREAD SAFE
	* Removes the packet at the specified index
	*/
	BinaryPacket * remove(uint32 index);

	/** THREAD SAFE
	* If we get a packet of channelData and its bigger than the current window size or
	* packet size in SocketSend, we have to break the packet up into smaller pieces and
	* re-insert those pieces back into the queue. For performance reasons, this function 
	* was moved out of SocketSend and placed here. Much more efficient.
	* The first packet in the queue will be split. It should have been previously inspected
	* with a peek()
	@param[in] firstSplitSize Total size of the first packet after splitting
	@param[in] Nth_splitSize The maximum amount of channel data that each 2nd and
		following pakcet can be split into
	*/
	int32 splitFirstPacket( 
		uint32 firstSplitSize,
		uint32 Nth_splitSize);

	/************************
	* SocketSend uses these variables and only SS
	************************/
	bool
		m_bLinkedToCNum;/**< If true, this queue is associated with a channel
						number */
	uint32
		m_cNum,			/**< Channel number this queue is associated with*/
		m_totalBytesInQ;/**< total number of bytes that the queue is holding. This
						is the total size of the BPs */

private:
	/**
	* Lets us dequeue a packet and tell the internal mutex to lock or not
	* based upon current state. This is here so that the splitPacket() can
	* re-use the internal dequeue() function
	*/
	BinaryPacket * dequeue(bool bIsMutexAlreadyLocked);

	pthread_mutex_t
		m_dataMutex;	/**< Mutex to make adding/removeing items thread-safe */
};

#endif
