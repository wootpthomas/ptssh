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

#ifndef _SOCKETSEND
#define _SOCKETSEND

/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"
#include "PTsshThread.h"

#include "CryptoStuff.h"



/*************************
 * Forward Declarations
 ************************/
class PTsshSocket;
class SocketRecieve;
class BinaryPacket;
class ChannelManager;
class Queue;

/**
* This class allows us an easy way to send data to the remote host. It hides the
* complexities of encryption, MAC signing and actually transmitting the packet. It
* also allows us to send data while recieving data in the SocketRecieve thread.
* 
* Note: All members in this class must be thread safe!
*/
class SocketSend: public PTsshThread
{
public:

	/**
	* Creates a socket send object.
	@param[in] pChannelMgr Pointer to our channel manager class. We us this to access
		channel related information
	@param[in] pActivityMutex Pointer to a mutex used to help with activity detection
	@param[in] pActivity_cv Pointer to a condition variable -> activity detection
	@param[in] pParent Pointer to the PTsshSocket parent class
	@param[in] sock Open and connected socket descriptor
	*/
	SocketSend(
		ChannelManager *pChannelMgr,
		pthread_mutex_t *pActivityMutex,
		pthread_cond_t *pActivity_cv,
		PTsshSocket *pParent,
		uint32 sock);

	/**
	* Destructor
	*/
	~SocketSend(void);

	/**
	* Inits the classes internal structures
	*/
	int32 init();

	/**
	* Sets the initial cipher object to use. This should be set before starting
	* this thread!
	*/
	void setInitialCipher(struct CryptoStuff::Cipher *pCipher) { m_pCipher = pCipher; }

	/** THREAD SAFE
	* Sets or changes the cipher object to use for encrypting & signing packets 
	*/
	void setCipher(struct CryptoStuff::Cipher *pCipher);

	/**
	* Note: Set this before starting this thread!!!!!
	*
	* Used to set the pointer to our SocketSend class. Essentially when we see a
	* SSH_MSG_KEXINIT packet, we signal our SocketSend class that we are beginning
	* a key exchange. It will then only send key exchange packets until such time
	* as it detects the SSH_NEW_KEYS message (success) or encounters a failure message
	*/
	void setSocketRecievePtr( SocketRecieve *pSR) { m_pSR = pSR; }

	/** THREAD SAFE
	* Used to put this thread into keyExchange mode. This thread will automatically
	* turn off key exchange mode when either a failure packet is sent or a SSH_NEW_KEYS
	* message is sent
	*/
	void beginKeyExchange();

	/**
	* Used to determine when the socket connection closed if it was planned or not.
	* Call this after you shutdown the SocketSend thread.
	@param [out] PTsshErrorCode A PTssh-friendly error code
	@param [out] socketErrorCode The actual underlying OS's error code that originated
		from the socket as a result of a failed send operation
	@return Returns True if the socket has shutdown and values were returned
	*/
	bool socketShutdownStatus(int32 &PTsshErrorCode, int &socketErrorCode);

	/**
	* Used to help the PTsshSocket class determine if we were disconnected
	* unexpectedly. Should only be called by the PTsshSocket class after this
	* thread has terminated. */
	bool bWasDisconnectSent() { return m_bDisconnectMsgSent; }

#ifdef PTSSH_STATISTICS
	void getStats(
		uint64 &rawPayloadBytes,
		uint64 &compressedPayloadBytes,
		uint64 &totalBytesOverWire);
#endif

#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
	/**
	* Note: Only SocketRecieve should call this!
	* This informs our SS thread that we should now begin compressing outbound
	* packets 
	*/
	void beginCompressingPackets();
#endif

protected:
	/**
	* This virtual function is expected to be present in the inheriting class. This
	* will be the event loop of your thread.
	*/
	void run();


private:

	/**
	* This takes all packets out of the m_outboundQ, MAC signs them, encryptes them
	* and places them in the m_pRawBufOut buffer. Once all packets have been packed
	* into the buffer, we write the entire filled portion of the buffer out to the socket */
	int32 combineAndSendPackets(bool &bDisconnectSent);

#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
	/**
	* If compression is enabled, this takes and compresses the binary packet's data
	*/
	int32 compressBP( Compress *pCompress, BinaryPacket **ppBP);
#endif

	
	/***********************
	* Variables
	***********************/
	ChannelManager 
		*m_pChannelMgr;		/**< Pointer to our Channel Manager class. This is how we
							access all data on or related to a channel. We do not
							own this pointer so don't delete it! 
							TODO: make this pointer correctly constant. */

	PTsshSocket
		*m_pPTsshSocket;		/**< Pointer to our parent class. We do not own this pointer
							and should never delete it. */

	SocketRecieve
		*m_pSR;				/**< Pointer to our SocketRecieve class. We use this to inform
							it when a keyexchange has finished so that it knows when to use
							its new cipher object */
	uint8
		*m_pRawBufOut,		/**< Pointer to our raw buffer. We will write multiple packets
							into this buffer and then send this buffer to the remote end */
		*m_pRawBufWriter,	/**< Pointer to the next spot that we can write in the buffer */
		m_tmpMAC[SHA_DIGEST_LENGTH];
							/**< Temp buffer for us to hold the calculated MAC address */

	uint32
		m_MBctr,
		m_sock,				/**<Socket file descriptor to do all sending on */
		m_sequenceNum,		/**< Sequence number. This is incremented after every packet
							transmitted/recieved */
		m_cDataCtr,			/**< Used to count the number of channel data bytes sent */
		m_rawBufLeft;		/**< Number of bytes left that we can fill with packets */


#ifdef PTSSH_STATISTICS
	uint64
		m_statsRawBytes,  /**< Holds the total number of uncompressed payload bytes 
							that would have been sent over the wire if the data was not 
							compressed. */
		m_statsCompressedBytes, /**< Holds the total number of compressed payload bytes
							that have been sent over the wire. */
		m_statsTotalBytes; /**< Holds the total number of bytes transmitted over the wire
						   thus far */
#endif

	int32
		m_error,			/**< Holds the last socket error */
		m_socketError, /**< Holds the value of the socket's shutdown result. IF we shutdown
							the socket, this will be PTSSH_SUCCESS. IF the socket died unexpectedly
							then this will be a PTSSH_ERR_* value.*/
		m_result;			/**< Holds the result of the last send. */


	bool
#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
		m_bSafeToCompress,  /**< Flag used to help us determine when we should
							start compressing packets. This is only checked if zlib is enabled
							and the compression scheme is zlib or zlib@openssh.com */
#endif
		m_bIsInKeyXMode,	/**< Flag used to check to see if we are in the middle of a
							key exchange sequence. If so, we only send keyX type packets */
		m_bDisconnectMsgSent;  /**< Flag to help us know when to expect the socket to 
							die. */
		

	pthread_mutex_t
		m_cipherMutex,		/**< Mutex used to safeguard the cipher object. We lock
							this mutex while encrypting or signing a packet and unlock
							it as soon as we are done. 
							We also use it to safeguard our m_bSafeToCompress
							flag. */
		m_inKeyXMutex,		/**< Mutex to safeguard toggeling our m_bIsInKeyXMode flag */
		*m_pActivityMutex;	/**< Mutex used in conjunction with m_activity_cv to help alert
							threads when activity is detected. 
							@\see PTssh::m_activity_cv	*/

	pthread_cond_t
		*m_pActivity_cv;	/**< This condition variable is used to help indicate activity.
							@see PTssh::m_activity_cv */

	Queue
		*m_pOutboundQ;			/**< Queue of packets that have been chosen to be globbed
								together in our temp buffer and transmitted to the remote
								side. This allows us to select from the list of packets in
								m_queue and send out multiple packets in a single write */

	struct CryptoStuff::Cipher
		*m_pCipher,			/**< Holds a pointer to our cipher object which holds our
							cipher algorithms to use and other cipher/MAC details */
		*m_pNewCipher;		/**< Holds the new cipher object that we will use after
							the current key exchange completes. */
};

#endif
