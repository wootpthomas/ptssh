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

#include "SocketSend.h"
#include "SSH2Types.h"

#ifdef WIN32
	#include <winsock2.h>
#else
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <errno.h>
#endif

#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif

#include "Compress.h"
#include "BinaryPacket.h"
#include "PTsshSocket.h"
#include "SocketRecieve.h"
#include "ChannelManager.h"
#include "Utility.h"
#include "Queue.h"
#include "PTsshLog.h"
#include "PTsshLog.h"

#include <openssl/hmac.h>
#include <assert.h>
#include <time.h>
#include <pthread.h>
#include <string.h>


#ifdef WIN32
/* Windows doesn't have a timespec struct, so define it here */
	//struct timespec {
	//	long tv_sec;
	//	long tv_nsec;
	//};
#else
	//Needed for usleep()
   #include <unistd.h>
#endif


///////////////////////////////////////////////////////////////////////////////
SocketSend::SocketSend(
	ChannelManager *pChannelMgr,
	pthread_mutex_t *pActivityMutex,
	pthread_cond_t *pActivity_cv,
	PTsshSocket *pParent,
	uint32 sock):
m_pChannelMgr(pChannelMgr),
m_pActivityMutex(pActivityMutex),
m_pActivity_cv(pActivity_cv),
m_pPTsshSocket(pParent),
m_sock(sock),
m_result(0),
m_error(0),
m_socketError(PTSSH_SUCCESS),
m_sequenceNum(0),
m_pCipher(NULL),
m_pNewCipher(0),
m_bIsInKeyXMode(true),
m_bDisconnectMsgSent(false),
m_pSR(0),
m_pRawBufOut(0),
m_pRawBufWriter(0),
m_rawBufLeft(0),
m_pOutboundQ(0),
m_cDataCtr(0),
m_MBctr(0)
#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
	,
	m_bSafeToCompress(false)
#endif
#ifdef PTSSH_STATISTICS
,
	m_statsRawBytes(0),
	m_statsCompressedBytes(0),
	m_statsTotalBytes(0)
#endif
{


}

///////////////////////////////////////////////////////////////////////////////
SocketSend::~SocketSend(void)
{
	if ( m_bInitOk)
	{
		pthread_mutex_destroy( &m_cipherMutex);
		pthread_mutex_destroy( &m_inKeyXMutex);
	}

	if ( m_pRawBufOut)
	{
		delete m_pRawBufOut;
		m_pRawBufOut = NULL;
		m_rawBufLeft = 0;
	}

	if ( m_pOutboundQ)
	{
		delete m_pOutboundQ;
		m_pOutboundQ = NULL;
	}

	if ( m_pCipher)
	{
#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
		if ( m_pCipher->pCompress)
		{
			delete m_pCipher->pCompress;
			m_pCipher->pCompress = NULL;
		}
#endif
		delete m_pCipher;
		m_pCipher = NULL;
	}

	if ( m_pNewCipher)
	{
		delete m_pNewCipher;
		m_pNewCipher = NULL;
	}
}

///////////////////////////////////////////////////////////////////////////////
int32
SocketSend::init()
{
	int32 result;
	if (pthread_mutex_init( &m_cipherMutex, 0) )
		goto error;
	if (pthread_mutex_init( &m_inKeyXMutex, 0) )
		goto error;

	m_pRawBufOut = new uint8[PTSSH_MAX_RAW_BUF_OUT_SIZE];
	if ( ! m_pRawBufOut)
		goto error;

	m_pRawBufWriter = m_pRawBufOut;
	m_rawBufLeft = PTSSH_MAX_RAW_BUF_OUT_SIZE;

	m_pOutboundQ = new Queue();
	if ( ! m_pOutboundQ)
		goto error;
	if ( m_pOutboundQ->init() != PTSSH_SUCCESS)
		goto error;

	result = PTsshThread::init();
	if ( result != PTSSH_SUCCESS)
		goto error;

	m_bInitOk = true;
	return PTSSH_SUCCESS;

error:
	pthread_mutex_destroy( &m_cipherMutex);
	pthread_mutex_destroy( &m_inKeyXMutex);

	if ( m_pRawBufOut)
	{
		delete m_pRawBufOut;
		m_pRawBufOut = NULL;
	}

	m_pRawBufWriter = NULL;
	m_rawBufLeft = 0;

	if (m_pOutboundQ )
	{
		delete m_pOutboundQ;
		m_pOutboundQ = NULL;
	}

	return PTSSH_ERR_CouldNotAllocateMemory;
}

///////////////////////////////////////////////////////////////////////////////
void
SocketSend::setCipher(struct CryptoStuff::Cipher *pCipher)
{
	pthread_mutex_lock( &m_cipherMutex);
		m_pNewCipher = pCipher;
	pthread_mutex_unlock( &m_cipherMutex);
}

///////////////////////////////////////////////////////////////////////////////
void
SocketSend::beginKeyExchange()
{
	pthread_mutex_lock( &m_inKeyXMutex);
		m_bIsInKeyXMode = true;
	pthread_mutex_unlock( &m_inKeyXMutex);

}

///////////////////////////////////////////////////////////////////////////////
bool
SocketSend::socketShutdownStatus(int32 &PTsshErrorCode, int &socketErrorCode)
{
	if ( ! isRunning() ) {
		socketErrorCode = m_error;
		PTsshErrorCode = m_socketError;
		return true;
	}
	else
		return false;
}

#ifdef PTSSH_STATISTICS
///////////////////////////////////////////////////////////////////////////////
void
SocketSend::getStats(
		uint64 &rawPayloadBytes,
		uint64 &compressedPayloadBytes,
		uint64 &totalBytesOverWire)
{
	rawPayloadBytes = m_statsRawBytes;
	compressedPayloadBytes = m_statsCompressedBytes;
	totalBytesOverWire = m_statsTotalBytes;
}
#endif

#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
///////////////////////////////////////////////////////////////////////////////
void
SocketSend::beginCompressingPackets()
{
	pthread_mutex_lock( &m_cipherMutex);
		m_bSafeToCompress = true;
	pthread_mutex_unlock( &m_cipherMutex);
}
#endif

///////////////////////////////////////////////////////////////////////////////
void 
SocketSend::run()
{
	bool 
		bKeepRunning = true,
		bAlreadyWaitedForMore = false,
		bInKeyXMode;
	BinaryPacket 
		*pBP = NULL;
	uint8 
		msgType = 0;
	uint32
		noPacketsInARow = 0,
		queueSize = 0,
		sleep_usec = PTSSH_SS_MIN_SOCKET_SLEEP_LENGTH;

	do 
	{
		if ( noPacketsInARow >= 2)
		{
			sleep_usec = PTSSH_SS_MIN_SOCKET_SLEEP_LENGTH * noPacketsInARow;
			if ( sleep_usec > PTSSH_SS_MAX_SOCKET_SLEEP_LENGTH)
				sleep_usec = PTSSH_SS_MAX_SOCKET_SLEEP_LENGTH;

			/* Sleep for a few microseconds... */
			microSecondSleep(sleep_usec);
		} 

		while ( m_rawBufLeft >= 52)
		{
			//Check to see if we are in key exchange mode
			pthread_mutex_lock( &m_inKeyXMutex);
				bInKeyXMode = m_bIsInKeyXMode;
			pthread_mutex_unlock( &m_inKeyXMutex);

			m_result = m_pChannelMgr->getNextPacket(
				bInKeyXMode, 
				m_rawBufLeft - m_pCipher->macLen,
				&pBP);
			if ( m_result != PTSSH_SUCCESS)
			{
				PTLOG((LL_error, "[SS] dying\n"));
				return;
			}

			if ( pBP)
			{
				noPacketsInARow = 0;
				sleep_usec = PTSSH_SS_MIN_SOCKET_SLEEP_LENGTH;

				//If we are in key exchange mode, check if this packet signals the end of keyX
				if ( bInKeyXMode)
				{
					if ( pBP->getSSHMessageType() == SSH_MSG_NEWKEYS)
					{
						//Yup, end of keyX. Turn off keyX mode so that we can queue other packets too
						pthread_mutex_lock( &m_inKeyXMutex);
							m_bIsInKeyXMode = false;
						pthread_mutex_unlock( &m_inKeyXMutex);
					}
				}

				m_result = m_pOutboundQ->enqueue( pBP);
				if ( m_result != PTSSH_SUCCESS)
				{
					PTLOG((LL_error, "[SS] Error: could not enqueue packet, dying!\n"));
					return;
				}
				else
				{
					uint32
						totalPackSize = pBP->getTotalPacketLength() + m_pCipher->macLen,
						bufSize = m_rawBufLeft;

					m_rawBufLeft -= pBP->getTotalPacketLength() + m_pCipher->macLen;
					if ( m_rawBufLeft > (PTSSH_MAX_OUTBOUND_QUEUE_SIZE<<1))
					{
						PTLOG((LL_warning, "[SS] Warning: More than allowed. BufSize=%d, packetSize=%d\n",
							bufSize, totalPackSize));
					}
					pBP = NULL;
				}
			}
			else
			{
				noPacketsInARow++;
				/* IF we were able to get a single packet from the queue and we haven't yet
				 * waited for a little bit, sleep for a tiny bit. This way we might be able to
				 * better fill our sending buffer */
				if ( ! bAlreadyWaitedForMore && m_pOutboundQ->size() <= 1)
				{
					bAlreadyWaitedForMore = true;
					microSecondSleep(PTSSH_SS_MIN_SOCKET_SLEEP_LENGTH);
				}
				else  //We got some packets, waited for a little bit, but no more were available.  Send what we have
					break;
			}
		}

		//Do we have packet(s) to send?
		queueSize = m_pOutboundQ->size();
		if ( queueSize)
		{
			/* Encrypt and write the packets in the buffer. This lets us send out
			 * multiple packets in a single write */
			m_result = combineAndSendPackets(bKeepRunning);

	//		//Check to see if we had any trouble sending the packet(s) out
	//		if ( m_result <= 0)
	//			break;
		}
		else
			m_result = 0;

		if ( m_result < 0)
		{
			bKeepRunning = false;
			PTLOG((LL_error, "[SS] Error: encountered an error; shutting down! Error %d\n", m_result));
		}
		else if ( m_bDisconnectMsgSent)
		{
			bKeepRunning = false;
			PTLOG((LL_debug3, "[SS] SSH disconnect sent, shutting down thread.\n"));
		}
		else
		{
			/* All packets were queued to the OS for sending, check to see if we should bail out
			 * and kill this thread */
			pthread_mutex_lock( &m_isRunningMutex);
				bKeepRunning = ( ! m_bStopRunning);
			pthread_mutex_unlock( &m_isRunningMutex);

			if ( ! bKeepRunning){
				PTLOG((LL_debug3, "[SS] Thread was asked to stop running.\n"));
			}
		}

	} while (bKeepRunning);

	PTLOG((LL_debug1, "[SS] Thread exiting\n"));
}

///////////////////////////////////////////////////////////////////////////////
/* TODO: PT performance optimization for multiple cores, pipeline the zipping,
 * MAC signing and compression operations */
int32
SocketSend::combineAndSendPackets(bool &bKeepRunning)
{
	int32
		result,
		socketSendLen = 0,
		totalSent = 0,
		totalInBuf = 0;
	uint32
		packetCtr = 0;
	BinaryPacket 
		*pBP;
	bool
		bChannelDataSent = false;

	while ( pBP = m_pOutboundQ->dequeue() )
	{
		//c* means cipher.. cipherBuffer ->cBuf
		uint32
			totalPacketLen = pBP->getTotalPacketLength();
		int32
			sendBufLen;
		packetCtr++;

		uint8
			msgType = *(pBP->getBP() + 5);
#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
		bool
			bSafeToCompress;
		
		if ( m_pCipher->m_compType == COMP_zlib_openssh)
		{
			pthread_mutex_lock( &m_cipherMutex);
				bSafeToCompress = m_bSafeToCompress;
			pthread_mutex_unlock( &m_cipherMutex);
		}
		else
			bSafeToCompress = m_bSafeToCompress;
#endif

		//PTLOG(("[SS] bytes left in rawbuffer %d (0x%X))\n", 
		//	PTSSH_MAX_RAW_BUF_OUT_SIZE - totalInBuf, PTSSH_MAX_RAW_BUF_OUT_SIZE - totalInBuf);

		if ( msgType == SSH_MSG_CHANNEL_DATA)
		{
			uint32 
				bytes = pBP->getChannelDataLen(),
				cNum = PTSSH_htons32( *((uint32*)(pBP->getBP() + 6)) );

			PTLOG((LL_debug4, "[SS:%d] Sending %uBytes, %uKB, %uMB total channel data, seq: %d\n",
				cNum, bytes, bytes>>10, bytes>>20, m_sequenceNum));


			m_cDataCtr += bytes;

			bChannelDataSent = true;
		}
		else if ( msgType == SSH_MSG_DISCONNECT)
		{
			m_bDisconnectMsgSent = true;
			bKeepRunning = false;
		}

#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
		//If compression is enabled, compress the binary packet
		if ( m_pCipher && m_pCipher->pCompress && bSafeToCompress)
		{
			//PTLOG((LL_debug3, "[SS] Compressing and sending packet type %d 0x%X\n", msgType, msgType));
			int32 result = compressBP( m_pCipher->pCompress, &pBP);
			if ( result != PTSSH_SUCCESS)
				return result;

			//uint8
			//	paddingLen = *(pBP->getBP() + 4);
			//ptLog(LL_debug3, "[SS] packet stats: paddingLen %d, payloadLen %d, totalLen %d\n",
			//	paddingLen, pBP->getPayloadLen(), pBP->getPacketLength());

			//Update our local packet length var
			totalPacketLen = pBP->getTotalPacketLength();
		}
		else
		{
			PTLOG((LL_debug3, "[SS] Sending packet type %d 0x%X\n", msgType, msgType));
		}
#endif


#ifdef PTSSH_STATISTICS
		m_statsTotalBytes += pBP->getTotalPacketLength();
#endif
		//ptLog("[SS] Packaging msg type %d for sending. Requires %d bytes\n", 
		//	msgType, totalPacketLen + m_pCipher->macLen);

		/* NOTE 1: The MAC portion of binary packets is not encrypted!
		 * The MAC is calculated on the entire unencrypted packet, including all
		 * fields except the MAC field itself. We place the MAC direcly in the 
		 * proper place in m_pRawBufOut
		From RFCs:
			mac = MAC(key, sequence_number || unencrypted_packet)  */
		if ( m_pCipher && m_pCipher->macLen)
		{
			HMAC_CTX ctx;
			unsigned char buf[4];

			//Set the "key"
			HMAC_Init( &ctx, m_pCipher->macKey, m_pCipher->macKeyLen, EVP_sha1() );

			//Hash the sequence_number in SSH uint32 format
			PTSSH_htons32( m_sequenceNum, (uint32*)buf);
			HMAC_Update( &ctx, buf, 4);
			
			//Hash the full binary packet
			HMAC_Update( &ctx, pBP->getBP(), totalPacketLen );

#ifdef _DEBUG
			if ( (m_pRawBufWriter + totalPacketLen + m_pCipher->macLen) > (m_pRawBufOut + PTSSH_MAX_RAW_BUF_OUT_SIZE))
			{
				PTLOG((LL_error, "[SS] HMAC: Went over the buffer by %d bytes\n", 
					(m_pRawBufWriter + totalPacketLen + m_pCipher->macLen) - (m_pRawBufOut + PTSSH_MAX_RAW_BUF_OUT_SIZE)));
				PTLOG((LL_error, "[SS] Buf start 0x%p, writer is at 0x%p, end is 0x%p\n",
					m_pRawBufOut, m_pRawBufWriter, m_pRawBufOut + PTSSH_MAX_RAW_BUF_OUT_SIZE));
				assert( false);
			}
#endif
			//Copy the MAC into the proper spot in the outbound buffer
			HMAC_Final( &ctx, m_pRawBufWriter + totalPacketLen, NULL );
			HMAC_cleanup( &ctx);
		}

		/* Encrypt the entire packet if we have enabled encryption. We will let the cipher
		 * function encrypt the bytes directly into the outbound buffer */
		if (m_pCipher && m_pCipher->pEncAlg)
		{
			sendBufLen = 0;

			EVP_EncryptUpdate( 
				&m_pCipher->ctx, 
				m_pRawBufWriter, 
				&sendBufLen, 
				(const unsigned char*) pBP->getBP(),
				totalPacketLen);

			//Increment our pointer just after this packet in the buffer
			m_pRawBufWriter += sendBufLen + m_pCipher->macLen;

#ifdef _DEBUG
			if ( m_pRawBufWriter > (m_pRawBufOut + PTSSH_MAX_RAW_BUF_OUT_SIZE))
			{
				PTLOG((LL_error, "[SS] Cipher: Went over the buffer by %d bytes\n", m_pRawBufWriter-(m_pRawBufOut + PTSSH_MAX_RAW_BUF_OUT_SIZE)));
				PTLOG((LL_error, "[SS] Buf start 0x%p, writer is at 0x%p, end is 0x%p\n",
					m_pRawBufOut, m_pRawBufWriter, m_pRawBufOut + PTSSH_MAX_RAW_BUF_OUT_SIZE));

				assert( false);
			}
#endif

			//Update the number of bytes that we will be writing to the socket
			socketSendLen += sendBufLen + m_pCipher->macLen;
		}
		else
		{
			if ( m_pCipher && m_pCipher->macLen)
				totalPacketLen += m_pCipher->macLen;

			//Copy in the packet
			memcpy(m_pRawBufWriter, pBP->getBP(), totalPacketLen);

			m_pRawBufWriter += totalPacketLen;
			socketSendLen += totalPacketLen;
		}

		/* Was this the final packet of the Key exchange? If so, we need
		 * to switch our cipher object so that the next packet uses the
		 * correct cipher */
		if ( msgType == SSH_MSG_NEWKEYS)
		{
			//Do we have a new Cipher object to use? If not, something is really fuct
			pthread_mutex_lock( &m_cipherMutex);
				assert (m_pNewCipher);
				if ( m_pNewCipher)
				{
					if ( m_pCipher)
					{
#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
						if (m_pCipher->pCompress)
						{
							delete m_pCipher->pCompress;
							m_pCipher->pCompress = NULL;
						}
#endif
						delete m_pCipher;
					}
					
					m_pCipher = m_pNewCipher;
					m_pNewCipher = NULL;
				}
			pthread_mutex_unlock( &m_cipherMutex);

#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
			/* If the compression type is Comp_zlib and we just sent the SSH_MSG_NEWKEYS
			* packet, then every packet after this should then be compressed */
			if ( m_pCipher->m_compType == COMP_zlib)
			{
				/* No need to lock/unlock because SR will not call the 
				beginCompressingPackets() when Comp type is Comp_zlib */
				m_bSafeToCompress = true;
				PTLOG((LL_debug2, "[SS] Enabling compression on outbound packets\n"));
			}
#endif
		}
		
		//Increment our sequence number
		m_sequenceNum++;

		//Delete the packet
		delete pBP;
		pBP = NULL;
	}

	//Do the actual packet sending
	while (totalSent < socketSendLen )
	{
		result = send(
			m_sock,
			(const char*)(m_pRawBufOut + totalSent),
			socketSendLen - totalSent,
			0);

		if (result <= 0)
		{
#ifdef WIN32
			m_error = WSAGetLastError();
			if ( m_error == WSAEWOULDBLOCK)
#else
			m_error = errno;
			if ( m_error == EAGAIN)
#endif
			{
				microSecondSleep(PTSSH_SS_MIN_SOCKET_SLEEP_LENGTH);
				
				continue;
			}
			else
			{
				/* IF we get here, the socket died while trying to send data */
				m_socketError = PTSSH_ERR_SocketDisconnectedUnexpectedly;
				bKeepRunning = false;
				return result;	//return error
			}
		}
		else
		{
			totalSent += result;
			m_MBctr += result;
		}
	}

	//if ( (totalSent>>10) < 97){
	//	ptLog("[SS] Sent %dKB, space left in buffer %dKB, window space left %dKB\n", 
	//		(totalSent>>10), ((m_pRawBufWriter-m_pRawBufOut)>>10), );
	//}

	if ( m_MBctr > 0x1000000)
	{
		uint32
			KBs = m_cDataCtr>>10,
			MBs = m_cDataCtr>>20;
		m_MBctr = 0;
		//PTLOG(("[SS] Sent a total of %lu bytes\n", m_cDataCtr));
		PTLOG((LL_debug2, "[SS] Total Sent: %uKB (%uMB)\n", KBs, MBs));
	}

//#ifdef PTSSH_STATISTICS
//	if ( m_statsCompressedBytes > 0x0)
//	{
//		ptLog("[SS] stats: raw %lld, compressed %lld, compression rate: %02f%%\n",
//			m_statsRawBytes, m_statsCompressedBytes, 
//			(1.0 - ((double)m_statsCompressedBytes / (double)m_statsRawBytes)) * 100 );
//	}
//#endif


	//if (bChannelDataSent)
	//{
	//	//Init the window adjust flag array
	//	for (int i = 0; i < PTSSH_MAX_CHANNELS; i++)
	//	{
	//		if (m_windowAdjustFlag[i])
	//		{
	//			m_windowAdjustFlag[i] = false;
	//			createWindowSpaceMsg(i);
	//		}
	//	}
	//}

	//Reset the pointers to our raw buffer
	m_rawBufLeft = PTSSH_MAX_RAW_BUF_OUT_SIZE;
	m_pRawBufWriter = m_pRawBufOut;

//#ifdef _DEBUG
//	memset(m_pRawBufWriter, 0x0, m_rawBufLeft);
//#endif

	return result;
}

///////////////////////////////////////////////////////////////////////////////
#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
int32
SocketSend::compressBP( Compress *pCompress, BinaryPacket **ppBP)
{
	int32 result = PTSSH_SUCCESS;

	uint8
		*pNewBPData = NULL;
	uint32
		newBPPayloadLen = 0,
		newBPTotalLen = 0;

	/**
	* PT performance note:
	* I'm really up in the air on which method to use for compressing packets. I
	* like the method that uses a temp buffer to do the compression in that then
	* will copy the compressed data into the original BP buffer -> no call to
	* allocate more memory which should keep memory fragmentation down... however
	* the code doesn;t seem to run any faster than the original method. 
	* I think this would be a nice part to take a peek at later on after I
	* implement pipelining to better make use of more than 1 core when sending
	* data */
#ifdef PTSSH_COMP_USE_COMP_TEMP_BUF
	/* Compress the payload of our BP and make sure that the new buffer that's
	* will be returned has enough room for the packet_len, padding and MAC */
	result = pCompress->deflate( *ppBP );
	if ( result != PTSSH_SUCCESS)
		return result;

	//Update our statistics
# ifdef PTSSH_STATISTICS
	m_statsRawBytes += (*ppBP)->getPayloadLen();
	m_statsCompressedBytes += newBPPayloadLen;
# endif

	return result;
#else
	/* Compress the payload of our BP and make sure that the new buffer that's
	* will be returned has enough room for the packet_len, padding and MAC */
	result = pCompress->deflate(
		(*ppBP)->getPayloadPtr(),
		(*ppBP)->getPayloadLen(),
		&pNewBPData,
		newBPPayloadLen,
		newBPTotalLen);
	if ( result != PTSSH_SUCCESS)
		return result;

	//Update our statistics
#ifdef PTSSH_STATISTICS
	m_statsRawBytes += (*ppBP)->getPayloadLen();
	m_statsCompressedBytes += newBPPayloadLen;
#endif

	//time to build a new BP, delete the old one
	delete *ppBP;
	*ppBP = new BinaryPacket();
	if ( *ppBP && (*ppBP)->init_deflate( pNewBPData, newBPTotalLen, newBPPayloadLen) )
	{
		return result;
	}
	else
		return PTSSH_ERR_CouldNotAllocateMemory;

#endif /* PTSSH_COMP_USE_COMP_TEMP_BUF */ 
}

#endif
