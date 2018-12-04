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

#ifndef _SFTPREQUESTMGR_H
#define _SFTPREQUESTMGR_H



/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"
#include "PTsshThread.h"
#include "Queue.h"
#include <pthread.h>

/*************************
 * Forward Declarations
 ************************/
class BinaryPacket;
class ChannelManager;
class LinkedList;

#ifdef PTSSH_SFTP

typedef struct {
	uint32
		requestID;
	Queue
		dataQ;
	pthread_mutex_t
		mutex;      /**< Mutex used to keep this item thread-safe and also be
					used in conjunction with the condition variable so that we
					can signal any interested thread when we get data */
	pthread_cond_t
		condVar;    /** Condition variable used to signal a listenting thread
					anytime we add data to the queue */
}RequestNode ;

class SftpRequestMgr: public PTsshThread
{
public:
	SftpRequestMgr(uint32 cNum, ChannelManager * const pChannelMgr);
	~SftpRequestMgr();

	int32 init();

	/** THREAD SAFE
	* Creates a new request. The request ID to use for this request
	* and a condition variable that you can use to block and be signaled upon
	* when data for the given request is recieved.
	@param[out] requestID Use this number to create the request
	@param[out] pCondVar Use this to do a blocking wait for data corresponding
		to the request ID
	@param[out] pMutex Use this to block while waiting for data corresponding
		to the request ID to arrive
	*/
	int32 createRequest(
		uint32 &requestID,
		pthread_cond_t **ppCondVar,
		pthread_mutex_t **ppMutex);

	/** THREAD SAFE
	* Lets the SftpRequesMgr know that no more requests will be made for the
	* specified request ID. The SftpRequestMgr can then free any resources used
	* for that request ID
	*/
	int32 deleteRequest(uint32 requestID);

	/** THREAD SAFE
	* Gets data out of the queue that corresponds to the given request ID
	*/
	int32 getRequestData(uint32 requestID, BinaryPacket **pBP);


private:
	/**
	* This is the thread's body that we operate in after a successful
	* init()
	*/
	void run();

	/**
	* IF a request comes in in the form of a Sftp data packet, it may have been
	* sent in multiple SSH channel data packets. This will wait until all packets
	* for the request have been recieved, or until an error occurs
	*/
	int32 waitForRequestData(RequestNode *pRN, uint32 &totalSftpBytesToRead, uint32 &sftpBytesRead);

	/**
	* Finds the request node in the linked list and points the ppRN pointer to
	* point to that node. That request node's mutex is locked and then the pointer
	* is returned. Calling function is expected to unlock the request node's mutex
	* when finished with the node
	*/
	int32 findRequestNode(uint32 requestID, RequestNode **ppRN);

	uint32
		m_cNum,      /**< Channel number that we listen for data on */
		m_requestID; /**< Counter used to keep track of and generate new
					 request IDs as needed */
	ChannelManager
		* const m_pChannelMgr;
					/**< Pointer to our channel manager. This is the object that we listen
					for channel data on; think Sftp data */
	pthread_mutex_t
		m_requestIdMutex,
					/**< Mutex used to make sure that only one thread at a time can
					increment our m_requestID */
		m_reqListMutex;
					/**< Mutex used to make sure access to our linked list class is
					thread-safe during request creation/deletion */

	LinkedList
		*m_pReqList; /**< A linked list of SFTP requests. When
					 a Sftp request is needed, we first register the request with this
					 class. Then we send our request. Helps make sure that it pulls
					 off the channel data from PTssh's channel manager and adds it in the
					 appropriate request array's queue. It will also alert any thread
					 that is waiting on data when data is received.*/
};

#endif /* PTSSH_SFTP */
#endif


