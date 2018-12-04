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

#ifndef _SOCKETRECIEVE
#define _SOCKETRECIEVE

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
class SocketSend;
class ChannelManager;
class BinaryPacket;


class SocketRecieve: public PTsshThread
{
public:
	/**
	* Creates a new instance of our socket recieve object.
	@param[in] pChannelMgr Pointer to our channel manager class. We us this to access
		channel related information
	@param[in] pActivityMutex Pointer to a mutex used to help with activity detection
	@param[in] m_pActivity_cv Pointer to a condition variable -> activity detection
	@param[in] pParent Pointer to the PTsshSocket parent class
	@param[in] sock Open and connected socket descriptor
	*/
	SocketRecieve(
		ChannelManager *pChannelMgr,
		pthread_mutex_t *pActivityMutex,
		pthread_cond_t *pActivity_cv,
		PTsshSocket *pParent,
		uint32 sock);

	/**
	* Destructor
	*/
	~SocketRecieve(void);

	/**
	* Inits all class vars
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
	void setSocketSendPtr( SocketSend *pSS) { m_pSS = pSS; }

	/**
	* Used to determine when the socket connection closed if it was planned or not.
	* Call this after you shutdown the SocketRecieve thread.
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
	bool bWasDisconnectRecieved() { return m_bDisconnectMsgRecieved; }

protected:
	/**
	* This virtual function is expected to be present in the inheriting class. This
	* will be the event loop of your thread.
	*/
	void run();

private:
	
	/**
	* Used to read the initial beginning of a new packet from the raw buffer. This will
	* perform decryption if needed. The m_pNewPacket buffer is allocated with enough
	* space for the new packet and the tidbit we decrypted is placed into it. You should
	* follow this function call with a fillNewPacket() call to try and fill as much of
	* the buffer as possible with any bytes in m_pRawBufIn that are left to process. */
	int32 createNewReadPacket();

	/**
	* Processes any bytes left in m_pRawBufIn, decrypts them and places them in the
	* m_pNewPacket buffer. Upon filling a packet, the MAC should then be checked with a
	* call to verifyNewPacketMAC();
	*/
	void fillNewPacket();

	bool verifyNewPacketMAC();

	bool newPacketIsFull();

	/**
	* Decrypts the specified number of bytes out of the raw buffer into
	* the specified buffer. Always make sure the bytesToDecrypt is evenly divisible
	* by the current blocksize!
	*/
	void decrypt( char *pBufPlain, uint32 bytesToDecrypt);

	/**
	* When this thread detects a SSH_MSG_NEWKEYS packet, it will call this
	* function to switch to its new cipher object.
	*/
	void endKeyExchange();

#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
	/**
	* If compression is enabled, this takes and uncompresses the binary packet's data
	*/
	int32 uncompressPacket(BinaryPacket **ppBP);

	bool
		m_bSafeToCompress;  /**< Flag used to help us determine when we should
							start compressing packets. This is only checked if zlib is enabled
							and the compression scheme is zlib or zlib@openssh.com */
#endif

	ChannelManager 
		*m_pChannelMgr;		/**< Pointer to our Channel Manager class. This is how we
							access all data on or related to a channel. We do not
							own this pointer so don't delete it! 
							TODO: make this pointer correctly constant. */
	PTsshSocket
		* m_pPTsshSocket;	/**< Pointer to our parent class. We do not own this pointer
							and should never delete it. */
	SocketSend 
		*m_pSS;				/**< Pointer to the SocketSend class that also uses our socket.
							We only use this so that we can call the class's beginKeyExchange()
							*/
	bool
		m_bDisconnectMsgRecieved;  /**< Flag to help us know when to expect the socket to 
							die. */

	uint8
		*m_pRawBufIn,		/**< Used as a buffer to read data into from the network. Normally
							this will be a mixture of ciphertext and MAC data. The purpose of
							this buffer is to be able to read a large amount of data from the
							socket. Since calling a socket's read function will make a call into
							kernel-land code, we want to get a large amount of data to work with
							so that we can minimize the downtime and let our cipher algorithm
							chug on a large amount, rather than a bunch of small pieces
							@/see m_pBufIter
							@/see m_rawBufLeft*/
		*m_pRawWriteIter,	/**< Points to the next available spot for writing data from the socket
							into our m_rawBufIn*/
		*m_pRawBufWorkIter,	/**< Points to the beginning of the bytes in m_pRawBufIn that are waiting
							to be processed by our cipher/MAC/compression algorithms */
		*m_pNewPacket,		/**< Pointer to the current new packet that we are filling from the
							socket */
		*m_pNewPacketWorkIter;/**< Pointer to the next available write position in the m_pNewPacket
							 buffer. We use this to write decrypted data. */
	uint32
#ifdef _DEBUG
		m_channelDataCtr,  /**< Used for debugging */
#endif
		m_rawLeftToProcess,	/**< Used to hold the number of bytes that are in m_pRawBufIn that are still
							waiting to be processed. The start of these bytes is found at m_pInWorkIter */
		m_pNewPacketLen,	/**< Used to keep track of the size of the buffer that m_pNewPacket holds */
		m_sock,				/**<Socket file descriptor to do all sending on */
		m_sequenceNum;		/**< Sequence number. This is incremented after every packet
							transmitted/recieved */

#ifdef PTSSH_STATISTICS
	uint64
		m_statsUncompressedBytes,  /**< Holds the total number of uncompressed bytes that would
								   have been sent over the wire if the data was not compressed. */
		m_statsCompressedBytes, /**< Holds the total number of compressed bytes that have been
								sent over the wire. */
		m_statsTotalBytes; /**< Holds the total number of bytes transmitted over the wire
						   thus far */
#endif

	int32
		m_socketError,	/**< Holds the socket error that caused us to leave our event loop */
		m_error;			/**< Holds the PTssh error code if we exited prematurely */
		
	pthread_mutex_t
		m_cipherMutex,		/**< Mutex used to safeguard the cipher object. We lock
							this mutex while encrypting or signing a packet and unlock
							it as soon as we are done.
							We also use this so safeguard the m_bSafeToCompress. */
		*m_pActivityMutex;	/**< Mutex used in conjunction with m_activity_cv to help alert
							threads when activity is detected. 
							@\see PTssh::m_activity_cv	*/

	pthread_cond_t
		m_cipher_cv,		/**< Ths CV is used to help us wait on a new cipher object if
							we go to switch to our new cipher object and we don;t have a new
							one yet.  */
		*m_pActivity_cv;	/**< This condition variable is used to help indicate activity.
							@see PTssh::m_activity_cv */

	struct CryptoStuff::Cipher
		*m_pCipher,			/**< Holds a pointer to our cipher object which holds our
							cipher algorithms to use and other cipher/MAC details */
		*m_pNewCipher;		/**< Holds the new cipher object that we will use after
							the current key exchange completes. */
};

#endif
