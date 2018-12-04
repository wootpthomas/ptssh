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

#ifndef _CHANNEL
#define _CHANNEL

/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"
//#include "Queue.h"

#include <pthread.h>


/*************************
 * Forward Declarations
 ************************/
class BinaryPacket;
class Queue;



struct PTsshChannelData{
	uint32 len;
	uint8* pData;
};

/**
* The Channel class is an abstraction of an SSH channel. It holds all data
* associated with the channel: EOF flag, max window size, max packet size and
* data buffers that hold packets of data waiting to be read. The methods/members
* in this class are all public. They should be safeguarded in ChannelManager.
*/
class Channel
{
public:

	enum ChannelStatus{
		CS_unknown = 0,
		CS_open = 1,                   /**< This is an active channel and we can send and receive data */
		CS_closed = 2,                 /**< This channel is closed and can not send or receive data */
		CS_failedToCreate = 3,         /**< This channel was not successfully created */
		CS_remoteForwardPlaceholder = 4/**< This channel is used to verify channel_open requests from the
									   server as a result of an incoming connection on a remote port
									   forward that we setup */
	};

	enum ChannelRequestResult{
		CRR_pending = 0,
		CRR_success = 2,
		CRR_failure = 3
	};

	Channel(uint32 initialWindowSize, PTsshChannelType type);
	~Channel(void);

	/**
	* This will init all member variables.
	@return Returns true on success, false on failure
	*/
	bool init(uint32 cNum);

	/*********************
	* Variables
	*********************/
	uint16
		m_forwardPort;			/**< Used only by forward-tcpip channels to help us verify when
								the server tries to open a channel with us that it corresponds
								to a request we made earlier for remote port forwarding */

	uint32
		//m_maxPacketSizeLocal,	/**< #define'd as PTSSH_MAX_PACKET_SIZE in PTsshConfig.h */
		m_maxPacketSizeRemote,
		m_windowSizeLocal,
		m_windowSizeRemote,		/**< The current widow size for this channel */
		m_channelNumberRemote,	/**< The corresponding remote SSH channel number identifier */
		m_maxInboundQueueSize,	/**< Specifies the total number of bytes that we allow to queue
								up in the inbound queues. When figuring out when to send window
								adjust messages, we inspect the amount of data in the queue and
								subtract it from this number. If that amount is positive, we then
								create and send a window adjust message so the remote end can send
								us more data. */
		m_maxOutboundQueueSize; /**< Specifies the total number of bytes that we allow to queue
								up in the outbound queue. If a process tries to add data and we are
								over our limit, we will block that process until there is either
								more window space available, or an error occurs. */

	pthread_mutex_t
		m_generalMutex,         /**< Used to safe-guard this class's member vars and keep it
								thread-safe */
		m_requestResultMutex,	/**< Used to help block on a particular channel for a
								response to a request. This way other channels can have
								pending requests and not block each other. Used together with
								m_requestResult_cv. */
		m_activityDataMutex,	/**< Used to make adding/removing data from the dataQueue
								thread-safe.
								We use this as the mutex that gets paired with the
								condition variable to implment blocking channel read requests
								for inbound data. */
		m_outboundQMutex,		/**< Used to help us block until we are able to insert data
								into the queue for sending. */
		m_EOFMutex,				/**< Used to help block until we get an EOF message on the channel */
		m_channelCloseMutex,	/**< Used to help block until we get a channel close message
								for the channel */
		m_activityStdErrorMutex;/**< Used to make adding/removing data from the m_stdErrorQueue
								thread-safe
								We use this as the mutex that gets paired with the
								condition variable to implment blocking channel read requests. */

	pthread_cond_t
		m_channelGeneral_cv,
		m_requestResult_cv,		/**< CV used to help us block until a request response is recieved */
		m_activityData_cv,		/**< Condition variable used to help us do blocking channel
								read requests for regular data. */
		m_outboundQ_cv,			/**< CV used to help us block/signal when we are allowed to put data into
								the queue */
		m_EOF_cv,				/**< CV used to help us block till we get a EOF message */
		m_channelClose_cv,		/**< CV Used to help block until we get a channel close message
								for the channel */
		m_activityStdError_cv;	/**< CV used to help us do blocking reads until some standard
								error channel data is available */

	PTsshChannelType
		m_channelType;

	bool
		m_bEOFRecieved,			/**< Boolean flag that is set to true if we ever recieve
								a SSH_MSG_CHANNEL_EOF packet, signaling the End-of-File
								on our channel */
		m_bChannelCloseRecvd,   /**< Flag used to indicate that a channel close message has
								been recieved. */
		m_bChannelCloseSent,   /**< Flag used to indicate if we have already sent a
						   SSH_CHANEL_CLOSE message for this channel */
		m_bSafeToSend,			/**< This flag is used exclusivley by the SocketSend class and only
								by SocketSend. It is used to help us refrain from sending packets
								if there isn't/wasn't window space available. It helps us keep from
								sending data packets out-of-order: if we go to send channelData on a
								channel, can;t because window size isn;t available, and then when we
								hit the next packet in the queue that holds channel data for that same
								channel and we have window space, don't send! */
		m_bForwardPlaceholder,  /**< Means that this channel is merely used as a placeholder so that
								we can lookup channel open messages from the server that claim to be
								the result of us setting up remote port forwarding (forwarded-tcpip)
								and the server saying hey, theres a connection! */
		m_bX11Forwarding;       /**< If true, X11 forwarding is enabled for this channel */

	char
		*m_pForwardIPAddr;		/**< Used only by forward-tcpip channels to help us verify when
								the server tries to open a channel with us that it corresponds
								to a request we made earlier for remote port forwarding */

	ChannelStatus
		m_channelStatus;		/**< See the ChannelStatus enum
								m_requestResultMutex safe-guards this variable. */
	ChannelRequestResult
		m_requestResult;		/**< Used to help us keep track of channel requests.
								This variable is safe-guarded with m_requestResultMutex
								and signaled on m_requestResult_cv */
	struct PTsshCallBackData
		*m_pCallbackData;       /**< Pointer to a struct that holds all the info we need to do a callback.
								this is mainly used for remote port forwarding notifications when a new
								channel is opened. */


	Queue
		*m_pInboundDataQueue,		/**< Data buffer queue that holds all general inbound data */
		*m_pInboundStdErrorQueue,	/**< Data buffer queue that holds all standard error data */
		*m_pOutboundQueue;			/**< Data buffer queue that holds all packets that are to be
									sent to the remote server.  */
};

#endif
