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
#include "SocketRecieve.h"
#include "Utility.h"
#include "PTsshSocket.h"
#include "SocketSend.h"
#include "ChannelManager.h"
#include "SSH2Types.h"
#include "BinaryPacket.h"
#include "Compress.h"
#include "PTsshLog.h"

#ifdef WIN32
#  include <winsock2.h>
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

#include <openssl/hmac.h>
#include <assert.h>
#include <string.h>

///////////////////////////////////////////////////////////////////////////////
SocketRecieve::SocketRecieve(
	ChannelManager *pChannelMgr,
	pthread_mutex_t *pActivityMutex,
	pthread_cond_t *pActivity_cv,
	PTsshSocket *pParent,
	uint32 sock):
m_pChannelMgr(pChannelMgr),
m_pPTsshSocket(pParent),
m_sock( sock),
m_socketError(0),
m_error(PTSSH_SUCCESS),
m_bDisconnectMsgRecieved(false),
m_pActivityMutex(pActivityMutex),
m_pActivity_cv(pActivity_cv),
m_sequenceNum(0),
m_pRawBufIn(0),
m_pRawWriteIter(0),
m_pRawBufWorkIter(0),
m_pNewPacket(0),
m_pNewPacketWorkIter(0),
m_pNewPacketLen(0),
m_pCipher(0),
m_pNewCipher(0),
m_rawLeftToProcess(0),
m_pSS(0)
#if defined (PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
	,
	m_bSafeToCompress(false)
#endif
#ifdef PTSSH_STATISTICS
	,
	m_statsUncompressedBytes(0),
	m_statsCompressedBytes(0),
	m_statsTotalBytes(0)
#endif
#ifdef _DEBUG
	,
	m_channelDataCtr(0)
#endif
{

}

///////////////////////////////////////////////////////////////////////////////
SocketRecieve::~SocketRecieve(void)
{
	if ( m_pRawBufIn)
	{
		delete m_pRawBufIn;
		m_pRawBufIn = NULL;
	}

	m_pChannelMgr = NULL;
	m_pPTsshSocket = NULL;
	m_pSS = NULL;
	m_pRawWriteIter = NULL;
	m_pRawBufWorkIter = NULL;
	m_pNewPacket = NULL;
	m_pNewPacketWorkIter = NULL;
	m_pActivityMutex = NULL;
	m_pActivity_cv = NULL;

	if ( m_pCipher)
	{
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
SocketRecieve::init()
{
	int32 result;
	//if (pthread_mutex_init( &m_queueMutex, 0) )return false;
	
	//Create a large buffer for reading in raw data
	m_pRawBufIn = new uint8[PTSSH_MAX_RAW_BUF_IN_SIZE];
	if ( ! m_pRawBufIn)
		return PTSSH_ERR_CouldNotAllocateMemory;

	if ( pthread_mutex_init( &m_cipherMutex, 0) != 0)
		goto error;
	if ( pthread_cond_init( &m_cipher_cv, 0) != 0)
		goto error;
	//if ( pthread_mutex_init( &m_incSeqNumMutex, 0) != 0)
	//	goto error;

	m_pRawWriteIter = m_pRawBufIn;
	m_pRawBufWorkIter = m_pRawBufIn;
	m_rawLeftToProcess = 0;

	result = PTsshThread::init();
	if ( result == PTSSH_SUCCESS)
		m_bInitOk = true;

	return result;

error:
	if ( m_pRawBufIn)
	{
		delete m_pRawBufIn;
		m_pRawBufIn = NULL;
	}

	pthread_mutex_destroy( &m_cipherMutex );
	pthread_cond_destroy( &m_cipher_cv );

	return PTSSH_ERR_CouldNotAllocateMemory;
}

///////////////////////////////////////////////////////////////////////////////
void
SocketRecieve::setCipher(struct CryptoStuff::Cipher *pCipher)
{
	pthread_mutex_lock( &m_cipherMutex);
		m_pNewCipher = pCipher;

		/* Signal that we have a new cipher object. This is useful if
		 * the SocketRecieve thread is waiting on a new cipher */
		pthread_cond_signal( &m_cipher_cv);
	pthread_mutex_unlock( &m_cipherMutex);

}

///////////////////////////////////////////////////////////////////////////////
bool
SocketRecieve::socketShutdownStatus(int32 &PTsshErrorCode, int &socketErrorCode)
{
	if ( ! isRunning() ) {
		socketErrorCode = m_socketError;
		PTsshErrorCode = m_error;
		return true;
	}
	else
		return false;
}

///////////////////////////////////////////////////////////////////////////////
void
SocketRecieve::endKeyExchange()
{
	pthread_mutex_lock( &m_cipherMutex);
		//Do we have a new Cipher object to use? If not, something is really fuct

		if ( ! m_pNewCipher)
		{
			//No new cipher object yet. Wait for the pSocket thread to give us one
			pthread_cond_wait( &m_cipher_cv, &m_cipherMutex);
		}

		assert (m_pNewCipher);
		if ( m_pNewCipher)
		{
			delete m_pCipher;
			m_pCipher = m_pNewCipher;
			m_pNewCipher = NULL;
		}
	pthread_mutex_unlock( &m_cipherMutex);
}

#if defined(PTSSH_ZLIB) || defined(PTSSH_ZLIB_OPENSSH)
///////////////////////////////////////////////////////////////////////////////
/*
packet_len = 32
paddin_len = 6
payload_len = 28
0x00BB7640  00 00 00 1c 06 78 9c 62 63 60 60 e0 29 2e ce d0 2d 2d 4e 2d 4a 2c 2d c9 00 08 8b  .....xœbc``à).ÎÐ--N-J,-É...
0x00BB765B  36 4f 08 48 eb
*/
int32
SocketRecieve::uncompressPacket(BinaryPacket **ppBP)
{
	int32 result = PTSSH_SUCCESS;

	uint8
		*pDataOut = NULL,
		paddingLen = *(m_pNewPacket+4);
	uint32
		dataOutLen = 0,
		totalBufSize = 0;

	//Need to take into account were the actual compressed payload is and how long that is
	//base that on the padding
	result = m_pCipher->pCompress->inflate(
		m_pNewPacket+5, m_pNewPacketLen-paddingLen-5, &pDataOut, dataOutLen, totalBufSize);
	if ( result == PTSSH_SUCCESS)
	{
		*ppBP = new BinaryPacket();
		if ( *ppBP && (*ppBP)->init_inflate(pDataOut, totalBufSize, dataOutLen) )
		{

		}
		else
			result = PTSSH_ERR_ZlibCompressionFailure;
	}
	else
	{
		PTLOG((LL_error, "[SR] error inflating packet: %d\n", result));
	}

	//Cleanup
	delete m_pNewPacket;
	m_pNewPacketLen = 0;


	return result;
}
#endif

///////////////////////////////////////////////////////////////////////////////
void
SocketRecieve::run( )
{
	int
		result = 0;
	uint32
		totalRawBytesRead = 0,	//total number of bytes that were read during this function call
		sleep_usec = PTSSH_SS_MIN_SOCKET_SLEEP_LENGTH,
		noDataReadsInARow = 0;	/* Number of successive times we tried to read from the 
										 * socket and no data was available */
	bool 
		bKeepGoing = true;


	do 
	{
		bool 
			bResult,
			bErrorOccured;
		uint8
			macLen = 0;
		int32 
			decryptedLen = 0,
			bytesLeftToRead = 0,
			bytesRead = 0,
			spaceInRawBuf = PTSSH_MAX_RAW_BUF_IN_SIZE - m_rawLeftToProcess,
			maxRead;

		if ( noDataReadsInARow >= 2)
		{
			/* We only get here if this is the 3rd (or more) time in a row that
			 * we tried to read data from the socket and there was nothing waiting
			 * for us to read. Instead of hammering the socket asking for data, we
			 * will sleep this thread for a little bit and then resume our checking */
			sleep_usec = PTSSH_SR_MIN_SOCKET_SLEEP_LENGTH * noDataReadsInARow;
			if ( sleep_usec > PTSSH_SR_MAX_SOCKET_SLEEP_LENGTH)
				sleep_usec = PTSSH_SR_MAX_SOCKET_SLEEP_LENGTH;

			/* Sleep for a few microseconds... */
			microSecondSleep(sleep_usec);
		} 

		/* Check to make sure we should keep running */
		pthread_mutex_lock( &m_isRunningMutex);
			bResult = m_bIsRunning;
		pthread_mutex_unlock( &m_isRunningMutex);

		if ( ! bResult)
			break;

		/* We only read a maximum number of bytes that fills to the end of the buffer
		 * and then we setup the pointers so that the next read will begin at the beginning
		 * of the raw buffer.*/
		if ( spaceInRawBuf == PTSSH_MAX_RAW_BUF_IN_SIZE)
		{
			//There are no bytes left to process, so let's start at the beginning
			//of the raw buffer. This helps to cut down on running wrap-around code
			maxRead = spaceInRawBuf;
			m_pRawWriteIter = m_pRawBufWorkIter = m_pRawBufIn;
		}
		else
		{
			if ( (m_pRawWriteIter + spaceInRawBuf) >= (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE))
				maxRead = (uint32) ((m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE) - m_pRawWriteIter);
			else
				maxRead = spaceInRawBuf;
		}

		//Read as much data from the socket as possible
		bytesRead = recv(m_sock, (char*)m_pRawWriteIter, maxRead, 0);

		//Check for error. If WSAEWOULDBLOCK, then theres no further data available from the socket
		if ( bytesRead <= 0) {
			if ( bytesRead < 0) {			
#ifdef WIN32
				m_socketError = WSAGetLastError();
				if (m_socketError == WSAEWOULDBLOCK && m_rawLeftToProcess < m_pCipher->blockSize) {
					noDataReadsInARow++;
					continue;
				}
				else if ( m_socketError != WSAEWOULDBLOCK)
#else
				m_socketError = errno;
				if (m_socketError == EAGAIN && m_rawLeftToProcess < m_pCipher->blockSize){
					noDataReadsInARow++;
					continue;
				}
				else if ( m_socketError != EAGAIN)
#endif
				{
					PTLOG((LL_debug1, "[SR] Socket disconnected\n"));
					PTLOG((LL_error, "[SR] Socket Recieve encountered an error during recv() and is shutting down! Error %d\n", m_socketError));

					break;
				}
				else
					PTLOG((LL_error, "[SR] Unhandled socket result!\n"));
			}
			else  //bytesRead == 0 -> socket gracefully closed
				break;
		}
		else if ( bytesRead < 0)
		{
			/* bytesRead is -1, no data available at this time.  */
			//PTLOG((LL_error, "[SR] bytesRead %d. What do I do %d?!\n", bytesRead, noDataReadsInARow));
			noDataReadsInARow++;
			continue;
		}
		else
		{
			//We read something! Advance our pointers and counters
			m_rawLeftToProcess += bytesRead;
			m_pRawWriteIter += bytesRead;
			totalRawBytesRead += bytesRead;

			//Reset our No-reads in a row counter
			noDataReadsInARow = 0;

			//Did the m_pRawWriteIter just go off the end of the buffer?
			if ( m_pRawWriteIter == (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE))
				m_pRawWriteIter = m_pRawBufIn;
#ifdef _DEBUG
			else if (m_pRawWriteIter > (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE)) {
				PTLOG((LL_error, "[SR] m_pRawWriteIter went over the end of the buffer in readFromSock!\n"));
			}
#endif

			/* The idea here is this: When we read from the socket, we read as much as possible
			 * into a buffer. Now the raw buffer could have a partial packet, or it could have
			 * many packets. So we work on as much of the raw buffer as possible. When the raw
			 * buffer has less than blocksize bytes in it, we go back to trying to read data
			 * from the socket */
			bErrorOccured = false;
			while ( m_rawLeftToProcess >= m_pCipher->blockSize && bKeepGoing)
			{
				//Do we have a packet to fill?
				if ( ! m_pNewPacket)  //NO
				{
					//Try and create a new packet based on the RAW data we read from the socket
					int32 result = createNewReadPacket();
					if ( result != PTSSH_SUCCESS) //Need more data or an error occured
					{
						PTLOG((LL_error, "[SR] Error allocation memory for new inbound packet\n"));
						m_error = result;

						bErrorOccured = true;
						break;
					}

					//We used some of the raw bytes in our buffer, do we have enough to keep going?
					if ( m_rawLeftToProcess < m_pCipher->blockSize)
					{
						//Nope, need at least blocksize bytes. Break and wait for more data
						break;
					}
				}

				/* If we get here, we have allocated a newPacket buffer and partially filled it.
				 -or-
				 We just entered in a read cycle and hope to further fill a packet */
				//Test and make sure the packet is not yet full
				if ( ! newPacketIsFull() )
					fillNewPacket();

				//We might have just filled a packet, test again
				if ( newPacketIsFull() )
				{
					/* Are there enough bytes waiting to be processed to get the MAC?
					 * MAC needs at least m_pCipher->macLen bytes */
					if ( m_rawLeftToProcess >= m_pCipher->macLen )
					{
						m_rawLeftToProcess -= m_pCipher->macLen;

						if ( verifyNewPacketMAC() )
						{
							BinaryPacket 
								*pBP = NULL;
							uint8 
								msgType = 0x0;

							//Bump our sequence number
							m_sequenceNum++;
#if defined (PTSSH_ZLIB) || defined(PTSSH_ZLIB_OPENSSH)
							if ( m_pCipher && m_pCipher->pCompress && m_bSafeToCompress)
							{
								int32 result = uncompressPacket(&pBP);
								if (result != PTSSH_SUCCESS){
									bErrorOccured = true;
									break;
								}
							}
							else
#endif /* PTSSH_ZLIB || PTSSH_ZLIB_OPENSSH */
							{
								//Compression is not enabled, build a new BP from the buffer
								//Put the new packet in a BinaryPacket
								pBP = new BinaryPacket();
								if ( ! pBP || ! pBP->init( m_pNewPacket, m_pNewPacketLen) )
								{
									result = PTSSH_ERR_CouldNotAllocateMemory;
									
									bErrorOccured = true;
									break;
								}
							}

							//Get the message type from our BP
							msgType = pBP->getSSHMessageType();

							//A little packet processing before we queue this packet
							switch (msgType) {
								case SSH_MSG_KEXINIT: //key exchange init packet
									PTLOG((LL_debug2, "[SR] Key exchange START\n"));
									m_pSS->beginKeyExchange();
									break;
								case SSH_MSG_NEWKEYS:
									//This will switch our cipher object to the new one
									endKeyExchange();

									PTLOG((LL_debug2, "[SR] Key exchange END\n"));


#ifdef PTSSH_ZLIB
									if ( m_pCipher && m_pCipher->m_compType == COMP_zlib)
									{
										/* Our SocketSend thread will have started compressing packets right after
										 * sending the SSH_MSG_NEWKEYS packet. No need to call
										 beginCompressingPackets() */
										m_bSafeToCompress = true;
										PTLOG((LL_debug2, "[SR] Packets from now on will be decompressed. Comp type is zlib\n"));
									}
#endif /* PTSSH_ZLIB */
								
									break;
#ifdef PTSSH_ZLIB_OPENSSH
								case SSH_MSG_USERAUTH_SUCCESS:
									if ( m_pCipher && m_pCipher->m_compType == COMP_zlib_openssh)
									{
										//Inform our SocketSend thread that it is now safe to compress packets
										m_pSS->beginCompressingPackets();
										m_bSafeToCompress = true;
										PTLOG((LL_debug2, "[SR] Packets from now on will be decompressed. Comp type is zlib@openssh.com\n"));
									}
									break;
#endif /* PTSSH_ZLIB_OPENSSH */
								case SSH_MSG_DISCONNECT:
									bKeepGoing = false;
									m_bDisconnectMsgRecieved = true;
									PTLOG((LL_debug2, "[SR] disconnect message received!\n"));
									break;
#ifdef _DEBUG
								case SSH_MSG_CHANNEL_DATA:
									m_channelDataCtr += pBP->getChannelDataLen();
									PTLOG((LL_debug4, "[SR] Recieved %uBytes, %uKB, %uMB total channel data, seq: %d\n",
										m_channelDataCtr,
										m_channelDataCtr>>10,
										m_channelDataCtr>>20,
										m_sequenceNum));
									break;
#endif
							}

							//PTLOG((LL_debug3, "[SR] Recieved packet type %d (0x%02X))\n",
							//	msgType, msgType);

							//Add the packet to the inbound Queue for later processing
							m_pPTsshSocket->enqueueInboundPacket( pBP);

							pthread_mutex_lock( m_pActivityMutex);
								pthread_cond_signal( m_pActivity_cv);
							pthread_mutex_unlock( m_pActivityMutex);

							m_pNewPacket = NULL;
						}
						else
						{
							m_error = PTSSH_ERR_PacketMAC_failed;
							PTLOG((LL_error, "[SR] MAC failed, packet might have been tampered with!\n"));
							
							//Wake up our main thread so that it can detect our epic fail
							pthread_mutex_lock( m_pActivityMutex);
								pthread_cond_signal( m_pActivity_cv);
							pthread_mutex_unlock( m_pActivityMutex);

							bKeepGoing = false;
							break;
						}
					}
				}
			}
		}
	} while (bKeepGoing);

	//Check to see if we were supposed to shut down
	pthread_mutex_lock( &m_isRunningMutex);
	if ( ! m_bStopRunning)
	{
		/* Check and see if the SS thread is not running. If it's stopped, then don;t bother
		* alerting the main thread, it should already know that somethings up. This could also
		* be a normal shutdown
		*/
		if ( m_pSS->isRunning())
		{
			/* The SocketSend thread is still running. This could be because its packaging
			 * up packets to send or because its sleeping. Either way, tell it to die because
			 * the socket is dead*/
			PTLOG((LL_error, "[SR] Telling the SocketSend thread to exit\n"));
			m_pSS->stopThread();
		}
	}
	else
		PTLOG((LL_error, "[SR] Asked to exit...shutting down normally\n"));
	pthread_mutex_unlock( &m_isRunningMutex);

	PTLOG((LL_debug1, "[SR] Thread exiting\n"));
}

///////////////////////////////////////////////////////////////////////////////
void
SocketRecieve::decrypt( char *pBufPlain, uint32 bytesToDecrypt)
{
	/* We will use this buffer if the portion being decrypted falls on the very
	 * end of our m_pRawBuf buffer and part of the beginning of m_pRawBuf. If this
	 * is the case, the data is copied into this buffer */
	char
		pTempBuf[PTSSH_MAX_BLOCK_SIZE*2],
		*pWorkIter = NULL;
	bool
		bIsDataSplit = false;
	int
		resultUpdate;
	uint32
		decryptLen = bytesToDecrypt,
		bytesOnEndOfBuf,
		bytesStage1 = 0,
		bytesStage2 = 0;

	/*** Decryption stages *****
	* Because we are using a large buffer in a circular manner, we have to check and
	* handle 2 cases:
	*   1) ciphertext in buffer doesn't wrap back around (stage3 only)
	*   2) ciphertext wraps: we need to decrypt some number of bytes on the end of
	*      the buffer and some number on the beginning. (stages 1,2,3)
	* For the 2nd case above, we may have to do it in 3 stages:
	*  1) decrypt an even "blocksize" number of bytes from middle to nearly the end of buffer
	*  2) decrypt a blocksize made up of a handful of bytes on the end and beginning of
	*     the buffer.
	*  3) decrypt from near the beginning, to the end of raw bytes (even blocksize of course)
	*/
	//Does the ciphertext wrap in our buffer? Case2 : Case1
	if ( (m_pRawBufWorkIter + bytesToDecrypt) > (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE))
	{
		bytesStage1 = (uint32) ( ((m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE) - m_pRawBufWorkIter) / m_pCipher->blockSize);
		bytesStage1 *= m_pCipher->blockSize;

		//Is there enough raw bytes at the end of the buffer to decrypt a few blocksize bytes of cipher text?
		if ( bytesStage1)
		{
			//Decrypt stage1 bytes
			resultUpdate = EVP_Cipher(
				&m_pCipher->ctx,
				(unsigned char *)pBufPlain,
				(const unsigned char *)m_pRawBufWorkIter,
				bytesStage1);

			m_pRawBufWorkIter += bytesStage1;
			m_rawLeftToProcess -= bytesStage1;
			bytesToDecrypt -= bytesStage1;
		}

		if ( m_pRawBufWorkIter == (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE))
		{
			//Don't need stage2, decryption ended evenly on end of our circular buffer
			//WorkIter wraps back to beginning of buffer
			m_pRawBufWorkIter = m_pRawBufIn;
		}
#ifdef _DEBUG
		else if (m_pRawBufWorkIter > (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE))
			PTLOG((LL_error, "[SR] m_pRawBufWorkIter went past the end of its buffer in createNewReadPacket!\n"));
#endif
		else
		{
			//For stage2, we need to combine the end&beginning bytes into one contiguous memory region
			bytesStage2 = m_pCipher->blockSize;
			bytesOnEndOfBuf = (uint32) ((m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE) - m_pRawBufWorkIter);

			//Make sure the bytes on the end of the buffer is less than our blocksize
			assert ( bytesOnEndOfBuf < m_pCipher->blockSize);

			memcpy(pTempBuf, m_pRawBufWorkIter, bytesOnEndOfBuf);
			//WorkIter wraps back to beginning of buffer
			m_pRawBufWorkIter = m_pRawBufIn;
			memcpy(pTempBuf + bytesOnEndOfBuf, m_pRawBufWorkIter, m_pCipher->blockSize - bytesOnEndOfBuf);
			
			//Reposition the m_pRawBufWorkIter
			m_pRawBufWorkIter += (m_pCipher->blockSize - bytesOnEndOfBuf);

			//Decrypt stage2 bytes
			resultUpdate = EVP_Cipher(
				&m_pCipher->ctx,
				(unsigned char *)pBufPlain + bytesStage1,
				(const unsigned char *)pTempBuf,
				bytesStage2);

			m_rawLeftToProcess -= bytesStage2;
			bytesToDecrypt -= bytesStage2;
		}
	}

	//Decrypt stage3 bytes
	if ( bytesToDecrypt)
	{
		decryptLen = bytesToDecrypt;

		//Make sure the bytes to decrypt is evenly divisible by the blocksize
		assert ( ! (bytesToDecrypt % m_pCipher->blockSize));
		resultUpdate = EVP_Cipher(
			&m_pCipher->ctx,
			(unsigned char *)pBufPlain + bytesStage1 + bytesStage2,
			(const unsigned char *)m_pRawBufWorkIter,
			decryptLen);

		m_rawLeftToProcess -= decryptLen;

		m_pRawBufWorkIter += decryptLen;
		if (m_pRawBufWorkIter == (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE))
			m_pRawBufWorkIter = m_pRawBufIn;		//Reposition the m_pRawBufWorkIter
#ifdef _DEBUG
		else if (m_pRawBufWorkIter > (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE)) {
			PTLOG((LL_error, "[SR] m_pRawBufWorkIter went past the endo of its buffer in createNewReadPacket!\n"));
		}
#endif
	}
}

///////////////////////////////////////////////////////////////////////////////
int32
SocketRecieve::createNewReadPacket()
{
	//int32
	//	resultUpdate;
	char
		pBufPlain[PTSSH_MAX_BLOCK_SIZE*2];

	if ( m_pCipher->pEncAlg)  //Is encryption enabled?
	{
		//We need to decrypt blocksize number of bytes, so that we can get the packet_length
		//Once we have this, we can create a new read packet buffer and then start filling it.
		decrypt( pBufPlain, m_pCipher->blockSize);
	}
	else
	{
		//Decryption is not active, fake out the code ;p
		//Copy the data into pBufPlain as if decryption took place

		//Is the "blockSize" of data on the very end & very beginning? (data is split)
		if ( (m_pRawBufWorkIter + m_pCipher->blockSize) >= (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE))
		{
			uint32 bytesOnEndOfBuf = (uint32) ((m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE) - m_pRawBufWorkIter);
			memcpy(pBufPlain, m_pRawBufWorkIter, bytesOnEndOfBuf);
			//WorkIter wraps back to beginning of buffer
			m_pRawBufWorkIter = m_pRawBufIn;
			memcpy(pBufPlain + bytesOnEndOfBuf, m_pRawBufWorkIter, m_pCipher->blockSize - bytesOnEndOfBuf);
			//Reposition the m_pRawBufWorkIter
			m_pRawBufWorkIter = m_pRawBufIn + (m_pCipher->blockSize - bytesOnEndOfBuf);
		}
		else
		{
			memcpy(pBufPlain, m_pRawBufWorkIter, m_pCipher->blockSize);
			m_pRawBufWorkIter += m_pCipher->blockSize;

			//Does the BufWorkIter need to wrap?
			if (m_pRawBufWorkIter == (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE))
				m_pRawBufWorkIter = m_pRawBufIn;
#ifdef _DEBUG
			else if (m_pRawBufWorkIter > (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE)){
				PTLOG((LL_error, "[SR] m_pRawBufWorkIter went past the endo of its buffer in createNewReadPacket!\n"));
			}
#endif

		}
		m_rawLeftToProcess -= m_pCipher->blockSize;
	}

	//We should be able to get the packet length and allocate a new buffer to fill
	uint32 packetLen = PTSSH_htons32( *((uint32*)pBufPlain) );
#ifdef _DEBUG
	assert( packetLen <= PTSSH_MAX_PACKET_SIZE + 32);
#endif
	//Calculate the bytes left to read to create this complete packet
	m_pNewPacketLen = (4 + packetLen);

	m_pNewPacket = new uint8[m_pNewPacketLen];
	if ( ! m_pNewPacket)
		return PTSSH_ERR_CouldNotAllocateMemory;

	//Move our writing pointer to next available space
	m_pNewPacketWorkIter = m_pNewPacket;

	//Copy in the decrypted bytes. Here we fill starting with packet_length
	//and copy in all that we decrypted. 
	memcpy( m_pNewPacketWorkIter, pBufPlain, m_pCipher->blockSize);
	m_pNewPacketWorkIter += m_pCipher->blockSize;

	/* Now at this point, we have allocated enough space for the packet that we are in the process
	* of reading from the socket. We have also written the first decryptedLen bytes. Return success */
	return PTSSH_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
bool
SocketRecieve::newPacketIsFull()
{
	//If the writing pointer is one byte past the end of our buffer, the m_pNewPacket buffer is full
	return m_pNewPacketWorkIter == (m_pNewPacket + m_pNewPacketLen);
}

///////////////////////////////////////////////////////////////////////////////
void
SocketRecieve::fillNewPacket()
{
	/* We can only work with even blocksizes of packets, and also keep in mind that
	* the MAC portion should not be decrypted. So we can either decrypt up to the number
	* of bytes left to fill the packet, or the m_rawLeftToProcess of bytes */

	uint32 
		fillLen,
		fillNeeded = (uint32) ((m_pNewPacket + m_pNewPacketLen) - m_pNewPacketWorkIter);

	if ( fillNeeded < m_rawLeftToProcess)
		fillLen = fillNeeded;
	else
		fillLen = m_rawLeftToProcess;

	//m_rawLeftToProcess
	if ( m_pCipher->pEncAlg)  //Is encryption enabled?
	{
		//Calculate the length we can safely decrypt
		fillLen = (fillLen / m_pCipher->blockSize) * m_pCipher->blockSize;

		decrypt( (char*)m_pNewPacketWorkIter, fillLen);
		m_pNewPacketWorkIter += fillLen;
	}
	else
	{
		//Is the data on the very end & very beginning? (data is split)
		if ( (m_pRawBufWorkIter + fillLen) > (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE))
		{
			uint32 bytesOnEndOfBuf = (uint32) ((m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE) - m_pRawBufWorkIter);
			memcpy(m_pNewPacketWorkIter, m_pRawBufWorkIter, bytesOnEndOfBuf);
			
			//Reposition pointers
			m_pNewPacketWorkIter += bytesOnEndOfBuf;
			m_pRawBufWorkIter = m_pRawBufIn;	//WorkIter wraps back to beginning of buffer
			m_rawLeftToProcess -= bytesOnEndOfBuf;
			
			fillLen -= bytesOnEndOfBuf;
		}
		
		memcpy(m_pNewPacketWorkIter, m_pRawBufWorkIter, fillLen);
		
		//Reposition pointers
		m_pRawBufWorkIter += fillLen;
		m_pNewPacketWorkIter += fillLen;
		m_rawLeftToProcess -= fillLen;

		//Did the Raw iter spill off the end of the buffer?
		if (m_pRawBufWorkIter == (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE))
			m_pRawBufWorkIter = m_pRawBufIn;	//WorkIter wraps back to beginning of buffer
#ifdef _DEBUG
		else if (m_pRawBufWorkIter > (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE)){
			PTLOG((LL_error, "[SR] m_pRawBufWorkIter went past the endo of its buffer in fillNewPacket!\n"));
		}
#endif
	}
}

///////////////////////////////////////////////////////////////////////////////
bool
SocketRecieve::verifyNewPacketMAC()
{
	//Check the MAC of the message
	if ( m_pCipher->macLen > 0)
	{
		HMAC_CTX ctx;
		uint8 macLen = m_pCipher->macLen;
		unsigned char
			buf[4],
			macCompareBuf[SHA_DIGEST_LENGTH],
			macSocketBuf[SHA_DIGEST_LENGTH],
			*pTempBuf = NULL;/* We us this to point to where the MAC is. This will either be in
							  * the Raw buffer, or in the macSocketBuf if the MAC was located on
							  * The very end of the m_pRawBufIn and the very beginning (was split) */

		//Is the "macLen" of data on the very end & very beginning? (data is split)
		if ( (m_pRawBufWorkIter + macLen) > (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE))
		{
			uint32 bytesOnEndOfBuf = (uint32) ((m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE) - m_pRawBufWorkIter);
			memcpy(macSocketBuf, m_pRawBufWorkIter, bytesOnEndOfBuf);
			//WorkIter wraps back to beginning of buffer
			m_pRawBufWorkIter = m_pRawBufIn;
			memcpy(macSocketBuf + bytesOnEndOfBuf, m_pRawBufWorkIter, macLen - bytesOnEndOfBuf);
			
			//Reposition the m_pRawBufWorkIter
			m_pRawBufWorkIter = m_pRawBufIn + (macLen - bytesOnEndOfBuf);
			pTempBuf = macSocketBuf;
		}
		else
		{
			//The MAC isn't split, we can just point to it in the Raw buffer
			pTempBuf = m_pRawBufWorkIter;
			m_pRawBufWorkIter += macLen;

			if ( m_pRawBufWorkIter == (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE))
				//WorkIter wraps back to beginning of buffer
				m_pRawBufWorkIter = m_pRawBufIn;
#ifdef _DEBUG
			else if (m_pRawBufWorkIter > (m_pRawBufIn + PTSSH_MAX_RAW_BUF_IN_SIZE)){
				PTLOG((LL_error, "[SR] m_pRawBufWorkIter went past the endo of its buffer in verifyNewPacketMAC!\n"));
			}
#endif
		}

		//Calculate the MAC of our packet
		HMAC_Init( &ctx, m_pCipher->macKey, m_pCipher->macKeyLen, EVP_sha1() );

		PTSSH_htons32( m_sequenceNum, (uint32*)buf);
		HMAC_Update( &ctx, buf, 4);
		
		HMAC_Update( &ctx, (const unsigned char*)(m_pNewPacket), m_pNewPacketLen );

		HMAC_Final( &ctx, macCompareBuf, NULL );
		HMAC_cleanup( &ctx);

		//Does our calculated MAC match what was sent with the packet?
		int result = memcmp( pTempBuf, macCompareBuf, macLen);
		if ( result != 0)
			return false;
	}

	//MAC is not yet being used, or MAC verified
	return true;
}
