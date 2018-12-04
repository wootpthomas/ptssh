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
#include "Channel.h"
#include "Queue.h"
#include "PTsshConfig.h"

#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif


#include <pthread.h>

//#include "BinaryPacket.h"


///////////////////////////////////////////////////////////////////////////////
Channel::Channel(uint32 initialWindowSize, PTsshChannelType type):
m_maxPacketSizeRemote(0),
m_windowSizeLocal(initialWindowSize),
m_windowSizeRemote(0),
m_channelType(type),
m_requestResult(CRR_pending),
m_channelNumberRemote(0xFFFFFFFF),
m_bEOFRecieved(false),
m_channelStatus(CS_unknown),
m_bSafeToSend(true),
m_pInboundDataQueue(0),
m_pInboundStdErrorQueue(0),
m_maxInboundQueueSize(PTSSH_MAX_INBOUND_QUEUE_SIZE),
m_maxOutboundQueueSize(PTSSH_MAX_OUTBOUND_QUEUE_SIZE),
m_bChannelCloseRecvd(0),
m_bChannelCloseSent(0),
m_forwardPort(0),
m_pForwardIPAddr(0),
m_bForwardPlaceholder(false),
m_bX11Forwarding(false)
{


}

///////////////////////////////////////////////////////////////////////////////
Channel::~Channel(void)
{
	//Destroy the semaphores
	pthread_mutex_destroy( &m_requestResultMutex);
	pthread_mutex_destroy( &m_activityDataMutex);
	pthread_mutex_destroy( &m_outboundQMutex);
	pthread_mutex_destroy( &m_activityStdErrorMutex);
	pthread_mutex_destroy( &m_EOFMutex);
	pthread_mutex_destroy( &m_channelCloseMutex);
	pthread_mutex_destroy( &m_generalMutex);

	pthread_cond_destroy( &m_requestResult_cv);
	pthread_cond_destroy( &m_activityData_cv);
	pthread_cond_destroy( &m_outboundQ_cv);
	pthread_cond_destroy( &m_activityStdError_cv);
	pthread_cond_destroy( &m_EOF_cv);
	pthread_cond_destroy( &m_channelClose_cv);
	pthread_cond_destroy( &m_channelGeneral_cv);

	if ( m_pInboundDataQueue)
	{
		delete m_pInboundDataQueue;
		m_pInboundDataQueue = NULL;
	}

	if ( m_pInboundStdErrorQueue)
	{
		delete m_pInboundStdErrorQueue;
		m_pInboundStdErrorQueue = NULL;
	}

	if ( m_pOutboundQueue)
	{
		delete m_pOutboundQueue;
		m_pOutboundQueue = NULL;
	}

	if ( m_pForwardIPAddr)
	{
		delete m_pForwardIPAddr;
		m_pForwardIPAddr = NULL;
	}
}

///////////////////////////////////////////////////////////////////////////////
bool
Channel::init(uint32 cNum)
{
		//Init items
	if ( pthread_mutex_init( &m_requestResultMutex, 0) != 0)	return false;
	if ( pthread_mutex_init( &m_activityDataMutex, 0) != 0)		return false;
	if ( pthread_mutex_init( &m_outboundQMutex, 0) != 0)		return false;
	if ( pthread_mutex_init( &m_activityStdErrorMutex, 0) != 0)	return false;
	if ( pthread_mutex_init( &m_EOFMutex, 0) != 0)				return false;
	if ( pthread_mutex_init( &m_channelCloseMutex, 0) != 0)		return false;
	if ( pthread_mutex_init( &m_generalMutex, 0) != 0)	        return false;
	
	if ( pthread_cond_init( &m_requestResult_cv, 0) != 0)		return false;
	if ( pthread_cond_init( &m_activityData_cv, 0) != 0)		return false;
	if ( pthread_cond_init( &m_outboundQ_cv, 0) != 0)			return false;
	if ( pthread_cond_init( &m_activityStdError_cv, 0) != 0)	return false;
	if ( pthread_cond_init( &m_EOF_cv, 0) != 0)					return false;
	if ( pthread_cond_init( &m_channelClose_cv, 0) != 0)		return false;
	if ( pthread_cond_init( &m_channelGeneral_cv, 0) != 0)		return false;
	
	m_pInboundDataQueue = new Queue(cNum);
	if ( ! m_pInboundDataQueue)
		return false;
	if ( m_pInboundDataQueue->init() != PTSSH_SUCCESS)
		return false;

	m_pInboundStdErrorQueue = new Queue(cNum);
	if ( ! m_pInboundStdErrorQueue)
		return false;
	if ( m_pInboundStdErrorQueue->init() != PTSSH_SUCCESS)
		return false;

	m_pOutboundQueue = new Queue(cNum);
	if ( ! m_pOutboundQueue)
		return false;
	if ( m_pOutboundQueue->init() != PTSSH_SUCCESS)
		return false;

	return true;
}
