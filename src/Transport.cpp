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
#include "Transport.h"

#include <string.h>
#include <stdio.h>

#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif

#include "PTssh.h"
#include "BinaryPacket.h"
#include "ChannelManager.h"
#include "Queue.h"
#include "PTsshSocket.h"
#include "SSH2Types.h"
#include "Utility.h"
#include "CallbackNotifier.h"
#include "PTsshLog.h"

///////////////////////////////////////////////////////////////////////////////
Transport::Transport(PTssh *pParent, ChannelManager *pChannelMgr, pthread_mutex_t *pActivityMutex, pthread_cond_t *pActivity_cv):
PTsshThread(),
m_pPTssh( pParent),
m_pChannelMgr(pChannelMgr),
m_pUsername( 0),
m_pRemoteHostAddress( 0),
m_pSocket( 0),
m_serviceResponse(0),
m_pActivityMutex(pActivityMutex),
m_pActivity_cv(pActivity_cv),
m_bConnected(0),
m_pOutboundQ(0),
m_pInboundQ(0),
m_pAllowedAuthTypes(NULL)
{

}

///////////////////////////////////////////////////////////////////////////////
Transport::~Transport(void)
{
	//Destroy the mutexes
	for (int i = 0; i < MT_TOTAL_BLOCK_TYPES; i++)
		pthread_mutex_destroy( &m_blockers[i]);
	
	//Destroy the condition vars
	for (int i = 0; i < MT_TOTAL_BLOCK_TYPES; i++)
		pthread_cond_destroy( &m_condVars[i]);

	//Destroy Attributes
	pthread_attr_destroy( &m_threadAttributes);

	if (m_pRemoteHostAddress)
		delete m_pRemoteHostAddress;

	if (m_pUsername)
		delete m_pUsername;

	if ( m_pAllowedAuthTypes)
		delete m_pAllowedAuthTypes;

	if ( m_pOutboundQ)
	{
		while (m_pOutboundQ->size() > 0)
		{
			BinaryPacket *pBP = m_pOutboundQ->dequeue();
			if (pBP)
				delete pBP;
		}

		delete m_pOutboundQ;
		m_pOutboundQ = NULL;
	}

	if ( m_pInboundQ)
	{
		while (m_pInboundQ->size() > 0)
		{
			BinaryPacket *pBP = m_pInboundQ->dequeue();
			if (pBP)
				delete pBP;
		}

		delete m_pInboundQ;
		m_pInboundQ = NULL;
	}
}

///////////////////////////////////////////////////////////////////////////////
int32
Transport::init(
	const char *username,
	const char *remoteHostAddress,
	uint16 remotePort)
{
	m_pUsername = strdup(username);
	m_pRemoteHostAddress = strdup(remoteHostAddress);
	m_remotePort = remotePort;

	//TODO: Error handling stuff on failure

	/***************Initialize our pthreads stuff*************/
	if (pthread_attr_init( &m_threadAttributes) )	return false;

	//Init the mutexes
	for (int i = 0; i < MT_TOTAL_BLOCK_TYPES; i++)
		if (pthread_mutex_init( &m_blockers[i], 0) )return false;
	
	//Init the condition vars
	for (int i = 0; i < MT_TOTAL_BLOCK_TYPES; i++)
		if (pthread_cond_init( &m_condVars[i], 0) )	return false;

	//Init the mutexes
	if (pthread_mutex_init( &m_mutexOutboundQ, 0) )	return false;
	if (pthread_mutex_init( &m_mutexInboundQ, 0) )	return false;
	if (pthread_mutex_init( &m_mutexGeneralLock, 0) )	return false;

	m_pOutboundQ = new Queue();
	if ( ! m_pOutboundQ)
		return false;
	if ( m_pOutboundQ->init() != PTSSH_SUCCESS)
		return false;

	m_pInboundQ = new Queue();
	if ( ! m_pInboundQ)
		return false;
	if ( m_pInboundQ->init() != PTSSH_SUCCESS)
		return false;	

	return PTsshThread::init();
}

///////////////////////////////////////////////////////////////////////////////
int32 
Transport::connect()
{
	int32 response;
	if ( this->isRunning() )
	{
		PTLOG((LL_warning, "Warning! Transport thread already running! Stopping it and making new thread\n"));
		stopThread();
	}

	if ( ! startThread() )
	{
		PTLOG((LL_error, "Couldn't create main thread!\n"));
		return PTSSH_ERR_CouldNotCreateTransportThread;
	}

	//Wait on the first keyexchange to either pass or fail
	pthread_mutex_lock( &m_blockers[MT_sockConnectionRelated]);
	//Sleep till we get a signal to wake up
	pthread_cond_wait(  &m_condVars[MT_sockConnectionRelated], &m_blockers[MT_sockConnectionRelated]);
		response = m_connectResponse;
	pthread_mutex_unlock( &m_blockers[MT_sockConnectionRelated]);

	return response;
}

///////////////////////////////////////////////////////////////////////////////
int32
Transport::getAuthResult()
{
	int32 result;
	/* This will block until we get a socket error, or until we read a auth
	 * response from the incoming packets */
	pthread_mutex_lock( &m_blockers[MT_authResponse]);
	pthread_cond_wait( &m_condVars[MT_authResponse], &m_blockers[MT_authResponse]);
		result = m_authResponse;
	pthread_mutex_unlock( &m_blockers[MT_authResponse]);

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
Transport::getGlobalRequestResult()
{
	int32 result;
	/* This will block until we get a socket error, or until we read a auth
	 * response from the incoming packets */
	pthread_mutex_lock( &m_blockers[MT_globalRequestResponse]);
	pthread_cond_wait( &m_condVars[MT_globalRequestResponse], &m_blockers[MT_globalRequestResponse]);
		result = m_globalRequestResponse;
	pthread_mutex_unlock( &m_blockers[MT_globalRequestResponse]);

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
Transport::getServiceResult()
{
	int32 result;
	
	pthread_mutex_lock( &m_blockers[MT_serviceRequestResponse]);
	pthread_cond_wait( &m_condVars[MT_serviceRequestResponse], &m_blockers[MT_serviceRequestResponse]);
		result = m_serviceResponse;
	pthread_mutex_unlock( &m_blockers[MT_serviceRequestResponse]);

	return result;
}

///////////////////////////////////////////////////////////////////////////////
char *
Transport::getAllowedAuthTypes()
{
	char *pStr = NULL;
	if (m_pAllowedAuthTypes)
		pStr = strdup(m_pAllowedAuthTypes);

	return pStr;
}

///////////////////////////////////////////////////////////////////////////////
int32
Transport::createSignature(
	uint8 *pSigData, uint32 sigDataLen,
	uint8 *pPublicKeyBlob, uint32 pPublicKeyBlobLen,
	uint8 *pPrivateKeyBlob, uint32 pPrivateKeyBlobLen,
	uint8 **ppSig, uint32 &sigLen)
{
	if ( m_pSocket)
		return m_pSocket->createSignature(
			pSigData,
			sigDataLen,
			pPublicKeyBlob,
			pPublicKeyBlobLen,
			pPrivateKeyBlob,
			pPrivateKeyBlobLen,
			ppSig,
			sigLen);

	return PTSSH_FAILURE;
}

///////////////////////////////////////////////////////////////////////////////
int32
Transport::getServerHostKey( uint8**ppBuf, uint32 &bufLen, bool bAsMD5_hash)
{
	if ( m_pSocket)
		return m_pSocket->getServerHostKey(ppBuf, bufLen, bAsMD5_hash);

	return PTSSH_ERR_NullPointer;
}

///////////////////////////////////////////////////////////////////////////////
void
Transport::run()
{
	int32
		result = 0;
	bool
		bResult = false;

	//Ok, we are now in our very own thread! woot!

	m_pSocket = new PTsshSocket(
		m_pChannelMgr,
		this,
		m_pActivityMutex,
		m_pActivity_cv,
		m_pRemoteHostAddress,
		m_remotePort);

	if ( ! m_pSocket)
	{
		pthread_mutex_lock( &m_blockers[MT_sockConnectionRelated]);
		pthread_cond_signal(  &m_condVars[MT_sockConnectionRelated]);	//Signal blocked&sleeping thread it can continue
			m_connectResponse = PTSSH_ERR_CouldNotAllocateMemory;
		pthread_mutex_unlock( &m_blockers[MT_sockConnectionRelated]);

		return;
	}

	//Initialize our socket class
	result = m_pSocket->init();
	if ( result != PTSSH_SUCCESS)
	{
		pthread_mutex_lock( &m_blockers[MT_sockConnectionRelated]);
		pthread_cond_signal(  &m_condVars[MT_sockConnectionRelated]);	//Signal blocked&sleeping thread it can continue
			m_connectResponse = PTSSH_ERR_Could_not_resolve_remote_host_address;
		pthread_mutex_unlock( &m_blockers[MT_sockConnectionRelated]);

		delete m_pSocket;
		m_pSocket = NULL;
		return;
	}

	///*Lock the activity Mutex. This will guarantee that our while loop is entered in
	// * the correct state and also keep any calling thread from sending in a request
	// * too early for us to catch */
	//pthread_mutex_lock( m_pActivityMutex);

	//If successfully resolved, connect to server
	result = m_pSocket->connectToServer();
	if ( result != PTSSH_SUCCESS )
	{
		pthread_mutex_lock( &m_blockers[MT_sockConnectionRelated]);
		pthread_cond_signal(  &m_condVars[MT_sockConnectionRelated]);	//Signal blocked&sleeping thread it can continue
			m_connectResponse = result;
		pthread_mutex_unlock( &m_blockers[MT_sockConnectionRelated]);

		delete m_pSocket;
		m_pSocket = NULL;
		return;
	}

	/******************************
	Now we enter into the guts of our event loop. We will check our outbound
	queue for any requests to send and will also check our inbound buffers for
	data that's been recieved. 
	*******************************/
	BinaryPacket *pBP = NULL;
	bool 
		bFatalError = false,
		bSendError = false,
		bRecieveError = false,
		bKeepProcessing = true;
	
	while( ! bFatalError && bKeepProcessing)
	{
		/* Now we wait for activity until one of either:
		1) User thread asked us to shutdown
		2) SocketSend encounters a socket error
		3) SocketRecieve encounters a socket error
		4) SocketRecieve places a packet in the inbound queue for processing
		
		Calling condition wait will automatically and atomically unlock the mutex
		and will let this thread sleep until we get woken up form any of our 3
		threads that might signal us into action. When woken up, the mutex is 
		automatically and atomically locked */
		cond_timedwait(m_pActivity_cv, m_pActivityMutex, 500);
		//pthread_cond_wait( m_pActivity_cv, m_pActivityMutex);

		//PTLOG(("[Transport] Signaled into action!\n"));

		/********************
		* Inbound packets
		********************/
		processInboundData( bKeepProcessing);

		//Check to see if we should shutdown
		pthread_mutex_lock(&m_isRunningMutex);
			bKeepProcessing = ! m_bStopRunning;
		pthread_mutex_unlock(&m_isRunningMutex);

		if ( ! bKeepProcessing ||  ! m_pSocket->isAlive() )
		{
			int
				socketError = 0;
			PTLOG((LL_warning, "[Transport] Socket has shut down. Checking status\n"));
			if ( m_pSocket->isDisconnected(socketError))
			{
				void (*pCallBackFunc)(struct PTsshCallBackData *) = m_pPTssh->getCallbackFunction(ET_DISCONNECT);

				PTLOG((LL_error, "[Transport] Socket died unexpectedly. Error: %d\n", socketError));

				//Spawn off a worker thread to handle the callback function
				if ( pCallBackFunc) {
					CallbackNotifier *pNotify = new CallbackNotifier();
					if ( pNotify) {
						struct PTsshCallBackData *pCBD = new PTsshCallBackData(m_pPTssh);
						if ( pCBD) {
							pCBD->eventType = ET_DISCONNECT;
							
							pCBD->pCallBackFunc = pCallBackFunc;
							pCBD->pDeveloperData = m_pPTssh->getCallbackData(ET_DISCONNECT);
							
							if ( pNotify->init() == PTSSH_SUCCESS) 
							{
								pNotify->setCallbackData( pCBD );
								pNotify->startThread();
							}
							else
							{
								delete pNotify;
								delete pCBD;
							}


							pCBD = NULL;   //Thread will delete this when its done
							pNotify = NULL;//Thread will kamikaze when its done
						}
					}
				}

				/* Kick off the callback function to alert the end-developer's code that
				 * the socket disconnected unexpectedly */
			}

			m_pSocket->shutdown();
			bKeepProcessing = false;
		}
	}

	pthread_mutex_lock( &m_blockers[MT_sockConnectionRelated]);
	if ( ! m_bConnected)
	{
		/* We never fully connected, which means our main thread is still waiting for a response.
		 * Signal it that we have a response... epic fail! 
		 */
		pthread_cond_signal(  &m_condVars[MT_sockConnectionRelated]);	//Signal blocked&sleeping thread it can continue
	}
	pthread_mutex_unlock( &m_blockers[MT_sockConnectionRelated]);

	//Umm.... something seems kinda klunky here. TODO: revisit this on code cleanup
	pthread_mutex_unlock( m_pActivityMutex);

	cleanupAfterShutdown();
}

///////////////////////////////////////////////////////////////////////////////
void
Transport::cleanupAfterShutdown()
{
	//If a calling thread was blocking on an auth response, fail and release it
	m_connectResponse = SSH_MSG_USERAUTH_FAILURE;

	//If a calling thread was blocking on a service response, fail and release it
	m_bServiceResponse = false;

	//If a calling thread was blocking on a channel create response, fail and release it
	m_bChannelCreateResponse = false;

	////Release any blocked threads
	//for (int i = 0; i < MT_TOTAL_BLOCK_TYPES; i++)
	//	sem_post( &m_blockers[i]);

	delete m_pSocket;
	m_pSocket = NULL;
}

///////////////////////////////////////////////////////////////////////////////
/* The general form for how we work on packets is:
 - get the next packet from the queue...then
 1) figure out what type of packet it is
 2) put the data, if any, into the proper queue for later reading by the user (channel data)
 3) Release any semaphore lock and then re-acquire it. This releases any blocked
	calling threads with their answer they were waiting on and gets us ready for
	their next question. */
void
Transport::processInboundData(bool &bKeepProcessing)
{
	uint32 
		cNum,
		strLen = 0;
	int32 
		result;
	uint8
		*pTemp = NULL,
		msgType;

	BinaryPacket 
		*pBP = NULL;
	
	while ( pBP = m_pSocket->dequeueInboundPacket() )
	{
		if ( pBP->readByte(msgType) != PTSSH_SUCCESS)
		{
			PTLOG((LL_error, "[Transport] Died reading binary packet\n"));
			bKeepProcessing = false;
		}

		//PTLOG(("[Transport] Processing Message type %d\n", msgType));

		switch( msgType ){
			case SSH_MSG_DISCONNECT: /* Terminate the connection */
				handleDisconnect( pBP);
				bKeepProcessing = false;
				break;
			case SSH_MSG_SERVICE_ACCEPT: /* Response to a Service request */
				handleServiceAccept( pBP);
				break;
			case SSH_MSG_KEXINIT:
				PTLOG((LL_debug2, "[Transport] SSH key exchange start recieved\n"));
				m_pSocket->negotiateEncryptions( &pBP);
				m_pSocket->doKeyExchange_step1();
				break;
			case SSH_MSG_KEXDH_REPLY:
				PTLOG((LL_debug2, "[Transport] SSH key exchange DH reply recieved\n"));
				m_pSocket->doKeyExchange_step2( &pBP);
				break;
			case SSH_MSG_NEWKEYS:
				PTLOG((LL_debug2, "[Transport] SSH new keys recieved\n"));
				delete pBP;
				pBP = NULL;

				if ( ! m_bConnected)
				{
					pthread_mutex_lock( &m_blockers[MT_sockConnectionRelated]);
					m_bConnected = true;
					m_connectResponse = PTSSH_SUCCESS;
	
					//Signal that keyexchange is done
					pthread_cond_signal(  &m_condVars[MT_sockConnectionRelated]);
					pthread_mutex_unlock( &m_blockers[MT_sockConnectionRelated]);
				}
				break;

			
			case SSH_MSG_USERAUTH_SUCCESS:
				pthread_mutex_lock( &m_blockers[MT_authResponse]);
				pthread_cond_signal(&m_condVars[MT_authResponse]);		//signal blocked thread to wake up
					m_authResponse = msgType;
				pthread_mutex_unlock( &m_blockers[MT_authResponse]);	//un-block the calling thread waiting on response
				break;
/*  I'm not implementing the public key query thing because in this day-and-age
    it doesn't seem to be worth it. We'll rely on auths either working or failing
			case SSH_MSG_USERAUTH_PK_OK:   // 60: Same as SSH_MSG_USERAUTH_PASSWD_CHANGEREQ
*/
			case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
			case SSH_MSG_USERAUTH_FAILURE:
			case SSH_MSG_USERAUTH_BANNER:
				if (m_pAllowedAuthTypes)
				{
					delete m_pAllowedAuthTypes;
					m_pAllowedAuthTypes = NULL;
				}

				//Parse out important info from the BP
				pBP->readString( &m_pAllowedAuthTypes, strLen);
				pBP->readBool( m_bPartialAuthSuccess);

				pthread_mutex_lock( &m_blockers[MT_authResponse]);
				pthread_cond_signal(&m_condVars[MT_authResponse]);		//signal blocked thread to wake up
					m_authResponse = msgType;
				pthread_mutex_unlock( &m_blockers[MT_authResponse]);	//un-block the calling thread waiting on response
				break;
			
			/****************************
			* Channel Related Messages
			****************************/
			case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
				if (pBP->readUint32( cNum) == PTSSH_SUCCESS)
				{
					uint32 
						remoteChannelNum = 0xFFFFFFFF,
						remoteWinSize = 0xFFFFFFFF,
						maxPacketSize = 0xFFFFFFFF;
					if (pBP->readUint32(remoteChannelNum) == PTSSH_SUCCESS)
						m_pChannelMgr->setRemoteChannelNumber( cNum, remoteChannelNum);
					if (pBP->readUint32(remoteWinSize) == PTSSH_SUCCESS)
						m_pChannelMgr->setInitialRemoteWindowSize(cNum, remoteWinSize);
					if (pBP->readUint32(maxPacketSize) == PTSSH_SUCCESS)
						m_pChannelMgr->setMaxPacketSizeRemote( cNum, maxPacketSize);

					PTLOG((LL_debug3, "[TR] Recieved channel open message on localNum %d, remoteNum %d, winSize %d, maxPacket %d\n",
						cNum, remoteChannelNum, remoteWinSize, maxPacketSize));

					//We set this last because it will release any blocked threads waiting on the result
					m_pChannelMgr->setChannelCreateResult( cNum, true);
				}

				break;

			case SSH_MSG_CHANNEL_OPEN_FAILURE:
				if (pBP->readUint32( cNum) == PTSSH_SUCCESS)
				{
					//We set this last because it will release any blocked threads waiting on the result
					m_pChannelMgr->setChannelCreateResult( cNum, false);
				}
				break;

			case SSH_MSG_CHANNEL_WINDOW_ADJUST:
				if (pBP->readUint32( cNum) == PTSSH_SUCCESS)
				{
					uint32 value;
					if (pBP->readUint32(value) == PTSSH_SUCCESS)
					{
						m_pChannelMgr->adjustWindowSizeRemote(cNum, value);
						PTLOG((LL_debug4, "[TR] Channel %d, Window adjust by %d bytes\n", cNum, value));
					}
				}
				break;
			
			case SSH_MSG_CHANNEL_DATA:
				if (pBP->readUint32( cNum) == PTSSH_SUCCESS)
				{
#ifdef _DEBUG
					//PTLOG(("[Transport] Recieved %d bytes of channel data on channel %d\n", pBP->getChannelDataLen(), cNum));
#endif
					result = m_pChannelMgr->queueInboundData(cNum, pBP, false);
					pBP = NULL;
					if ( result != PTSSH_SUCCESS)
						bKeepProcessing = false;
				}
				break;
			case SSH_MSG_CHANNEL_EXTENDED_DATA:
				if (pBP->readUint32( cNum) == PTSSH_SUCCESS)
				{
					result = m_pChannelMgr->queueInboundData(cNum, pBP, true);
					pBP = NULL;
					if ( result != PTSSH_SUCCESS)
						bKeepProcessing = false;
#ifdef _DEBUG
					else
						PTLOG((LL_debug2, "[Transport] Recieved extended channel data on %d\n", cNum));
#endif
				}
				break;
			case SSH_MSG_CHANNEL_EOF:
				if (pBP->readUint32( cNum) == PTSSH_SUCCESS)
					m_pChannelMgr->setEOF_recieved(cNum);
				break;

			case SSH_MSG_CHANNEL_CLOSE:
				if (pBP->readUint32( cNum) == PTSSH_SUCCESS)
					m_pChannelMgr->setChannelCloseMsgReceived( cNum);
				break;
			
			case SSH_MSG_CHANNEL_SUCCESS:
				if (pBP->readUint32( cNum) == PTSSH_SUCCESS)
					m_pChannelMgr->setChannelRequestResult( cNum, true);
				break;

			case SSH_MSG_CHANNEL_FAILURE:
				if (pBP->readUint32( cNum) == PTSSH_SUCCESS)
					m_pChannelMgr->setChannelRequestResult( cNum, false);
				break;

			case SSH_MSG_REQUEST_SUCCESS:
				pthread_mutex_lock( &m_blockers[MT_globalRequestResponse]);
				pthread_cond_signal(&m_condVars[MT_globalRequestResponse]);		//signal blocked thread to wake up
					m_globalRequestResponse = PTSSH_SUCCESS;
				pthread_mutex_unlock( &m_blockers[MT_globalRequestResponse]);	//un-block the calling thread waiting on response
				break;

			case SSH_MSG_GLOBAL_REQUEST:
				PTLOG((LL_debug2, "[Transport] Unhandled SSH_MSG_GLOBAL_REQUEST message!\n"));
				break;
			case SSH_MSG_REQUEST_FAILURE:
				pthread_mutex_lock( &m_blockers[MT_globalRequestResponse]);
				pthread_cond_signal(&m_condVars[MT_globalRequestResponse]);		//signal blocked thread to wake up
					m_globalRequestResponse = PTSSH_FAILURE;
				pthread_mutex_unlock( &m_blockers[MT_globalRequestResponse]);	//un-block the calling thread waiting on response
				break;

			case SSH_MSG_DEBUG:
				PTLOG((LL_debug2, "[Transport] SSH debug message recieved\n"));

			case SSH_MSG_CHANNEL_OPEN:
				/* The only time that we should really see this is if we have a
				 * forwarded-tcpip connection setup by the server and the server
				 * is alerting us of a pending connection */
				PTLOG((LL_debug2, "[Transport] Got an open channel request!"));
				handleChannelOpenRequest(pBP);
				break;

			case SSH_MSG_SERVICE_REQUEST: /* Message types we ignore since we are not a server */
			case SSH_MSG_USERAUTH_REQUEST:
			
			case SSH_MSG_CHANNEL_REQUEST:
							
			case SSH_MSG_IGNORE:	/* Message types that we discard */
			case SSH_MSG_UNIMPLEMENTED:
				break;
			default:
				PTLOG((LL_warning, "[Transport] Unhandled SSH message %d\n", msgType));
		}

		if ( pBP)
		{
			delete pBP;
			pBP = NULL;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
void
Transport::handleDisconnect( BinaryPacket * const pBP)
{
	pthread_mutex_lock( &m_blockers[MT_sockConnectionRelated]);
		m_bConnected = false;
		PTLOG((LL_info, "[Transport] SSH disconnect message recieved\n"));

		//Signal any process waiting on this message that we got a disconnect
		pthread_cond_signal( &m_condVars[MT_sockConnectionRelated]);
	pthread_mutex_unlock( &m_blockers[MT_sockConnectionRelated]);
}
			
///////////////////////////////////////////////////////////////////////////////
void
Transport::handleServiceAccept( BinaryPacket * const pBP)
{
	char 
		* pStr = NULL;
	uint32
		strLen;

	PTLOG((LL_debug2, "[Transport] SSH service accept message recieved\n"));
	
	pthread_mutex_lock( &m_blockers[MT_serviceRequestResponse]);
	pthread_cond_signal( &m_condVars[MT_serviceRequestResponse]);
		if ( pBP->readString( &pStr, strLen) == PTSSH_SUCCESS)
		{
			m_bServiceResponse = true;	//Indicate we got a response
			if ( pStr)
			{
				if ( memcmp( pStr, "ssh-userauth", strLen) == 0)
				{
					//m_serviceType = PTsshUserAuth;
					m_serviceResponse = PTSSH_SUCCESS;
				}
				else if ( memcmp( pStr, "ssh-connection", strLen) == 0)
				{
					//m_serviceType = PTsshConnection;
					m_serviceResponse = PTSSH_SUCCESS;
				}
				else
				{
					//m_serviceType = PTsshUnknown;
					m_serviceResponse = PTSSH_FAILURE;  //indicate failure
				}
			}
		}

		if (pStr)
			delete pStr;
	pthread_mutex_unlock( &m_blockers[MT_serviceRequestResponse]);
}

///////////////////////////////////////////////////////////////////////////////
/* The remote side then decides whether it can open the channel, and
   responds with either SSH_MSG_CHANNEL_OPEN_CONFIRMATION or
   SSH_MSG_CHANNEL_OPEN_FAILURE.

      byte      SSH_MSG_CHANNEL_OPEN_CONFIRMATION
      uint32    recipient channel
      uint32    sender channel
      uint32    initial window size
      uint32    maximum packet size
      ....      channel type specific data follows

   The 'recipient channel' is the channel number given in the original
   open request, and 'sender channel' is the channel number allocated by
   the other side.

      byte      SSH_MSG_CHANNEL_OPEN_FAILURE
      uint32    recipient channel
      uint32    reason code
      string    description in ISO-10646 UTF-8 encoding [RFC3629]
      string    language tag [RFC3066]
*/
void
Transport::handleChannelOpenRequest(BinaryPacket * const pBP)
{
	bool
		bSendChannelOpenFailure = true,
		bCloseChannel = false;
	char 
		*pChannelTypeStr = NULL,
		*pBoundAddr = NULL,
		*pOriginatorAddr = NULL;
	const char
		*pNotExpected ="The channel type was not expected",
		*pNotRequested="Remote port forwarding was not setup for the address and port",
		*pX11NotRequested="X11 forwarding was not requested",
		*pGeneralError="PTssh encountered an error and had to bomb out",
		*pError = pGeneralError;
		
	
	uint32
		cNum = PTSSH_BAD_CHANNEL_NUMBER,
		errorReasonCode = SSH_OPEN_RESOURCE_SHORTAGE,
		pChannelTypeStrLen = 0,
		pBoundAddrStrLen = 0,
		pOriginatorAddrStrLen = 0,
		remoteInitialWindowSize = 0,
		remoteMaxPacketSize = 0,
		remoteChannelNum = PTSSH_BAD_CHANNEL_NUMBER,
		remoteBoundPort = 0,
		remoteOriginatorPort = 0;

	//Parse out the packet's details
	pBP->readString( &pChannelTypeStr, pChannelTypeStrLen);
	pBP->readUint32( remoteChannelNum);
	pBP->readUint32( remoteInitialWindowSize);
	pBP->readUint32( remoteMaxPacketSize);

	//Make sure its an expected type
	if ( strcmp(pChannelTypeStr, "forwarded-tcpip") == 0)
	{
		pBP->readString( &pBoundAddr, pBoundAddrStrLen);
		pBP->readUint32( remoteBoundPort);
		pBP->readString( &pOriginatorAddr, pOriginatorAddrStrLen);
		pBP->readUint32( remoteOriginatorPort);

		//Verify the channel open address and port match a placeholder entry in our channel manager
		if ( m_pChannelMgr->isValidRemotePortForward(pBoundAddr, remoteBoundPort) )
		{
			//This is a valid remote port forward, create a channel and inform the channel's handler
			int32 result = m_pChannelMgr->newChannel(
				PTSSH_DEFAULT_WINDOW_SIZE,
				PTSSH_MAX_PACKET_SIZE,
				PTsshCT_forwarded_tcpip,
				cNum);
			if (result == PTSSH_SUCCESS)
			{
				//If we fail later on, make sure and close this channel
				bCloseChannel = true;

				//Set the rest of the remote's: channel properties, initial window size, max packet size
				m_pChannelMgr->setRemoteChannelNumber( cNum, remoteChannelNum);
				m_pChannelMgr->setInitialRemoteWindowSize(cNum, remoteInitialWindowSize);
				m_pChannelMgr->setMaxPacketSizeRemote(cNum, remoteMaxPacketSize);
				m_pChannelMgr->setChannelCreateResult(cNum, true);

				//Now tell the remote server that we accept the channel/remote-port-forward
				uint32 len =
					1 + //	    byte      SSH_MSG_CHANNEL_OPEN_CONFIRMATION
					4 + //      uint32    recipient channel
					4 + //      uint32    sender channel
					4 + //      uint32    initial window size
					4;  //      uint32    maximum packet size

				BinaryPacket *pBP_openChannel = new BinaryPacket();
				CallbackNotifier *pNotify = new CallbackNotifier();
				struct PTsshCallBackData *pCBD = NULL;
				m_pChannelMgr->getForwardNotifierCallbackData(pBoundAddr, remoteBoundPort, &pCBD);
				if ( pBP_openChannel && pBP_openChannel->init(len) && pNotify && pNotify->init() && pCBD )
				{
					pBP_openChannel->writeByte( SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
					pBP_openChannel->writeUint32( remoteChannelNum);
					pBP_openChannel->writeUint32( cNum);
					pBP_openChannel->writeUint32( PTSSH_DEFAULT_WINDOW_SIZE);
					pBP_openChannel->writeUint32( PTSSH_MAX_PACKET_SIZE);

					result = m_pChannelMgr->queueOutboundData(pBP_openChannel);
					if ( result == PTSSH_SUCCESS)
					{
						bSendChannelOpenFailure = false;
						bCloseChannel = false;

						/* Now create the Notifier thread and let it do its work. No need to
						 * worry about deleting it. It will delete itself once the callback
						 * function has been invoked */
						pCBD->channelNumber = cNum;

						pNotify->setCallbackData( pCBD );
						pNotify->startThread();

						pCBD = NULL;   //Thread will delete this when its done
						pNotify = NULL;//Thread will kamikaze when its done
					}
				}

				if (pNotify)
				{
					delete pNotify;
					pNotify = NULL;
				}
				if (pCBD)
				{
					delete pCBD;
					pCBD = NULL;
				}
			}
		}
		else
		{
			errorReasonCode = SSH_OPEN_ADMINISTRATIVELY_PROHIBITED;
			pError = pNotRequested;
		}
	}
	else if ( strcmp(pChannelTypeStr, "x11") == 0)
	{
		PTLOG((LL_info, "[Trans] Incoming X11 channel open request"));
		pBP->readString( &pOriginatorAddr, pOriginatorAddrStrLen);
		pBP->readUint32( remoteOriginatorPort);

		//Let's allocate a local channel
		int32 result = m_pChannelMgr->newChannel(
				PTSSH_DEFAULT_WINDOW_SIZE,
				PTSSH_MAX_PACKET_SIZE,
				PTsshCT_forwarded_tcpip,
				cNum);
		if (result == PTSSH_SUCCESS)
		{
			//Set the rest of the remote's: channel properties, initial window size, max packet size
			m_pChannelMgr->setRemoteChannelNumber( cNum, remoteChannelNum);
			m_pChannelMgr->setInitialRemoteWindowSize(cNum, remoteInitialWindowSize);
			m_pChannelMgr->setMaxPacketSizeRemote(cNum, remoteMaxPacketSize);
			m_pChannelMgr->setChannelCreateResult(cNum, true);

			bSendChannelOpenFailure = false;
			bCloseChannel = false;

			/* Let the PTssh X11handler function take it from here.
			 * Note:  One later enhancement, we can spin off a notification thread and
			 * let it call the x11handler, that way we can resume processing packets sooner.
			 */
			result = m_pPTssh->handleX11Connection( cNum);
		}
	}
	else
	{
		errorReasonCode = SSH_OPEN_UNKNOWN_CHANNEL_TYPE;
		pError = pNotExpected;
	}

	if (bCloseChannel )
		m_pChannelMgr->deleteChannel( cNum, false);

	if ( bSendChannelOpenFailure)
	{
		uint32 len =
			1 +                //	    byte      SSH_MSG_CHANNEL_OPEN_FAILURE
			4 +                //      uint32    recipient channel
			4 +                //      uint32    reason code
			4 + (uint32)strlen(pError)+//      string    description in ISO-10646 UTF-8 encoding [RFC3629]
			4;                 //      string    language tag [RFC3066]
		BinaryPacket *pBP_closeChannel = new BinaryPacket();
		if ( pBP_closeChannel && pBP_closeChannel->init(len) )
		{
			pBP_closeChannel->writeByte( SSH_MSG_CHANNEL_OPEN_FAILURE );
			pBP_closeChannel->writeUint32( remoteChannelNum);
			pBP_closeChannel->writeUint32( errorReasonCode);
			pBP_closeChannel->writeString( pError, (uint32) strlen(pError));
			pBP_closeChannel->writeString( NULL, 0);

			int32 result = m_pChannelMgr->queueOutboundData(pBP_closeChannel);
			if ( result != PTSSH_SUCCESS)
				delete pBP_closeChannel;
		}
	}

	if ( pChannelTypeStr)
		delete pChannelTypeStr;
	if ( pBoundAddr)
		delete pBoundAddr;
	if ( pOriginatorAddr)
		delete pOriginatorAddr;
}
