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

#ifndef _PTSSHSOCKET
#define _PTSSHSOCKET

/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"
#include <pthread.h>


/*************************
* Forward declarations
*************************/
class SocketSend;
class SocketRecieve;
class Transport;
class ChannelManager;
class CryptoStuff;
class BinaryPacket;
class Queue;
class Compress;


/**
PTsshSocket is responsible for making life a little easier by hiding the complexities
and such of dealing with data to and from the socket. It will also encrypt and decrypt
the data that is read/written to the socket. It will also take care of things like 
keyexchange requests without bothering any of the parenting classes above it.
*/
class PTsshSocket
{
public:

	/**
	* Creates an instance of this socket class meant to be connected
	* to the specified server and port.
	@param[in] pChannelMgr Pointer to our channel manager class. We us this to access
		channel related information
	@param[in] pTransport Pointer to our parent class
	@param[in] pActivityMutex Pointer to a mutex used to help with activity detection
	@param[in] m_pActivity_cv Pointer to a condition variable -> activity detection
	@param[in] address Pointer to a string containing either the IP
		address of the server (Ex: 10.0.0.1) or a URL to the server, like
		pthomas.pssh.is.neat.com
	@param[in] port Port number to use for the socket connection
	*/
	PTsshSocket(
		ChannelManager *pChannelMgr,
		Transport *pTransport,
		pthread_mutex_t *pActivityMutex,
		pthread_cond_t *m_pActivity_cv,
		char * address,
		uint16 port);

	/**
	* Destructor. Closes the socket, cleans up and dies!
	*/
	~PTsshSocket(void);

	/**
	* Inits the internal variables. This will aso try and initialize the socket,
	* which will try and resolve the given address and port to connect to.
	@return Returns PTSSH_SUCCESS on success or an error code on failure
	*/
	int32 init();

	/** THREAD SAFE
	* Returns true or false depending on if the socket is still connected and
	* active. IF both SocketSend and SocketRecieve threads have shut down, then
	* this will return false. If either thread is still running, then this will
	* return true.
	*/
	bool isAlive();

	/** THREAD SAFE
	* If the socket was disconnected unexpectedly, then this will return true. This is
	* used by the Transport class to determine if we should fire off a callback thread
	* to alert end-developer code of the socket being disconnected.
	* If we were disconnected unexpectedly, the socketError will have the error number
	* from the OS.
	*/
	bool isDisconnected( int32 &socketError);

	/**
	* This will return a string-list object that contains string representations
	* for all available supported encryption algorithms for the requested type.
	@param [in] type The encryption algorithm type you want to get
	@param [out] ppList A pointer to an array of character pointers. The list
		is terminated with a NULL character pointer entry. Calling function takes
		ownership of the character list and is responsible for its deletion.
	@see setAlgs()
	*/
	void getAlgs( ALG_Type type, char **ppList);

	/**
	* This sets the order that you want the server/client to use the algorithms. When
	* key exchange begins, we send a packet saying what encryption/mac/hostKey/... algorithms we
	* want to use and the order of preference. By calling this and setting the list,
	* will will try to use the first alrogithm if the server supports it, if not we
	* fallback to the next entry, and the next until failure or we find a common
	* algorithm that both sides support.
	@param [in] type The encryption algorithm type you want to set
	@param [in] ppList A pointer to an array of character pointers. The list
		is terminated with a NULL character pointer entry. The list should be a comma
		seperated list of the algorithms to use and in the order to try and use them.
		NOTE: PTsshSocket takes ownership of the passed in list and will delete it when needed.
	@return Returns true on success or false on failure.
	@see getAlgs()
	*/
	bool setAlgs( ALG_Type type, char *ppList);

	/**
	* Gets the agreed upon algorithm for encryption, client -> server
	*/
	EncType getCrypt_CtoS()
	{ return m_KN_encrypt_CtoS; }

	/**
	* Gets the agreed upon algorithm for encryption, server -> client
	*/
	EncType getCrypt_StoC()
	{ return m_KN_encrypt_StoC; }

	/**
	* Gets the agreed upon algorithm for compression, client -> server
	*/
	COMP_Type getCompression_CtoS()
	{ return m_KN_comp_CtoS; }

	/**
	* Gets the agreed upon algorithm for compression, server -> client
	*/
	COMP_Type getCompression_StoC()
	{ return m_KN_comp_StoC; }



	/**
	* Gets a compression object for the specified communication direction
	*/
	int32 getCompressionObj(bool bIsClientToServer, Compress **pComp);

	/**
	* Gives us an easy way to find out if compression is enabled or not
	*/
	bool isCompressionEnabled(bool bIsClientToServer);

	/**
	* Attempts to create a connection to the remote address and port to 
	* use for SSH communication. After establishing a successful connection,
	* it will send our banner and try and receive the remote banner. If banner
	* exchange is successful, it then returns a positive number indicating
	* success.
	@return Returns positive on successful connection, else error code
	@see resolveServerAddr()
	*/
	int32 connectToServer();

	/**
	* After we successfully connect to the remote server, we start the algorith negotiation
	* so each side knows what encryption types are supported. If that succeeds, then it
	* will also kick off the rest of the keyexchange process.
	@param[in] pBP_kexinit Pointer to the remote's kexinit binary packet
	@return Returns true if we sent our encryption list and we recieved the remote hosts
	*/
	int32 negotiateEncryptions(BinaryPacket **pBP_kexinit);
	
	/** THREAD SAFE
	* Adds a packet to our inbound queue. Only the SocketRecieve class should be
	* calling this function! The packet is in SSH Binary Packet format.
	@param[in] pPacket pointer to a packet to add to the queue
	@return Returns true on success, false on failure
	*/
	int32 enqueueInboundPacket( BinaryPacket * pPacket);

	/** THREAD SAFE
	* Looks in the inbound queue and returns the first packet waiting to be processed.
	* If no packet is found, it returns Null.
	@return Returns a pointer to a packet if one exists in the queue.
	*/
	BinaryPacket* dequeueInboundPacket();

	/**
	* This will do a key exchange or a key re-exchange in the case that we are currently
	* connected and have already done a successfuly key exchange.
	@return Returns a positive number on success or the error
	*/
	int32 doKeyExchange_step1();
	int32 doKeyExchange_step2(BinaryPacket **ppBP);

	/**
	* Stops SocketSend and SocketRecieve threads and deletes them
	*/
	void shutdown();

	/**
	* Gets the session ID from our CryptoStuff obj
	*/
	int32 getSessionID(uint8 **ppSessionID, uint32 &sessionLen);

	/**
	* Creates a signature over the given data. CryptoStuff does most of the work
	*/
	int32 createSignature(
		uint8 *pSigData,
		uint32 sigDataLen,
		uint8 *pPublicKeyBlob, uint32 pPublicKeyBlobLen,
		uint8 *pPrivateKeyBlob, uint32 pPrivateKeyBlobLen,
		uint8 **ppSig,
		uint32 &sigLen);

	/**
	* Makes a copy of the server's host key. Default format is an MD5 hash, otherwise
	* a SHA-1 Hash of the server's host key is returned. 
	*/
	int32 getServerHostKey( uint8**ppBuf, uint32 &bufLen, bool bAsMD5_hash);

private:
	/*********************
	* Private Functions
	*********************/

	/**
	* This writes raw data to the socket. This is only used during connect() for sending
	* our banner message
	*/
	int rawSocketWrite( const char *pRAW, uint32 len);

	/**
	* Used to get the remote servers banner */
	int32 readBanner(char **pBuf);

	/**
	* Fills in the binary packet with our supported encryptions for the purpose of
	* sending over a SSH key exchange packet.
	@param [in] pBP A pointer to an allocated BinaryPacket struct
	*/
	void buildKeyExchangePacket( BinaryPacket *pBP);

	/**
	* When a response is recieved from the server in the form of a key exchange packet
	* we parse out the methods that the server supports and set our internal variables
	* so that we are ready for the next part in the key exchange process. This will also
	* delete the binary packet when its finished.
	@param [in] pBuf A pointer to a recieved binary packet
	*/
	int32 parseHostKeyExchangePacket( char *pBP);

	/**
	* Frees the memory in the character pointer and reallocates it with
	* the specified size.
	@param ppC A pointer to a character array
	@param size Size to make the new character array
	@return Returns true on success
	*/
	bool reallocate( char **ppC, uint32 size);
	
	/* Returns the enum-mapped value of the associated string */
	int32 setAlg(char *pStr);

	/* Sets the correct key exchange algorithm type for the passed in string 
	*/
	KEYX_Type setAlgKeyX(const char *pName);

	/* Sets the correct encryption algorithm type for the passed in string */
	EncType setAlgEncryption(const char *pName);

	/* Sets the correct HMAC algorithm type for the passed in string */
	MAC_Type setAlgHmac(char *pName);

	/* Sets the correct public key algorithm type for the passed in string 	*/	
	HOST_Type setAlgPublicKey(char *pName);

	/* Sets the correct compression algorithm type for the passed in string */	
	COMP_Type setAlgCompression(char *pName);

#ifdef PTSSH_SHOW_CONNECTION_DETAILS
	/* Gets a string representation of the key exchange name */
	const char * getAlgKeyX(KEYX_Type type);

	/* Gets the correct encryption algorithm type for the passed in string */
	const char * getAlgEncryption(EncType type);

	/* Gets the correct HMAC algorithm type for the passed in string  */
	const char * getAlgHmac(MAC_Type type);

	/* Gets the correct public key algorithm type for the passed in string 	*/	
	const char * getAlgPublicKey(HOST_Type type);

	/* Gets the correct compression algorithm type for the passed in string */	
	const char * getAlgCompression(COMP_Type type);
#endif /* PTSSH_SHOW_CONNECTION_DETAILS */

	char 
		*m_pAddress,
		*m_pRemoteBanner,
		
		/* The index order of these next two arrays is as follows:
		0 - kex_algorithms
		1 - server_host_key_algorithms
		2 - encryption_algorithms_client_to_server
		3 - encryption_algorithms_server_to_client
		4 - mac_algorithms_client_to_server
		5 - mac_algorithms_server_to_client
		6 - compression_algorithms_client_to_server
		7 - compression_algorithms_server_to_client
		8 - languages_client_to_server
		9 - languages_server_to_client */
		*m_pRH_kex[10],	/**< An array of character strings that holds the results
							of the remote host's algorithm negotiation packet */
		*m_pClient_kex[10],/**< An array of character strings that holds our supported
							algorithms for algorithm negotiation */
		*m_pHostKey,		/**< The remote server's host key. Set during Diffie-Hellman
							key exchange. */
		*m_pStrKeyX,       /**< Holds the agreed upon key exchange method */
		*m_pStrHostKey,    /**< Holds the agreed upon host key method */
		*m_pStrEncryptCtoS,/**< Holds the agreed upon encryption method client -> server */
		*m_pStrEncryptStoC,/**< Holds the agreed upon encryption method server -> client  */
		*m_pStrMacCtoS,    /**< Holds the agreed upon MAC method client -> server */
		*m_pStrMacStoC,    /**< Holds the agreed upon MAC method server -> client */
		*m_pStrCompCtoS,   /**< Holds the agreed upon compression method client -> server */
		*m_pStrCompStoC;   /**< Holds the agreed upon compression method server -> client */

	uint8
		m_blockSizeOut,		/**< Number of bytes used for outbound encryption */
		m_macSizeOut;		/**< Number of bytes used for the outbound MAC signing */

	uint16
		m_port;				/**< Number that specifies on which port we make our connection */

	int
		m_sock;

	/* KN - Key Negotiation values. Used during key exchange or re-exchange. */
	KEYX_Type
		m_KN_keyx;				/**< Agreed upon algorithms for key exchange */

	HOST_Type
		m_KN_hostKey;

	EncType
		m_KN_encrypt_CtoS,		/**< Agreed upon algorithm for encrypt from client to server*/
		m_KN_encrypt_StoC;		/**< Agreed upon algorithm for encrypt from server to client*/

	MAC_Type
		m_KN_mac_CtoS,			/**< Agreed upon alg for MAC client to server */
		m_KN_mac_StoC;			/**< Agreed upon alg for MAC server to client */

	COMP_Type
		m_KN_comp_CtoS,			/**< Agreed upon alg for compression client to server */
		m_KN_comp_StoC;			/**< Agreed upon alg for compression server to client */


	uint32
		m_remoteBannerLen,	/**< Holds the number of bytes in m_pRemoteBanner*/
		m_hostKeyLen;		/**< Holds the number of bytes in m_pHostKey*/

	struct sockaddr_in 
		*m_pSockAddr;		/**< Nasty work around: Couldn't get the sockaddr_in struct
							to correctly forward declare. So fuck it. I'll redneck it */

	bool
		m_bRecievedBanner,	/**< Initially this is false. Once we recieve the remote host's
							banner message, this becomes true. Once true, we then expect all
							incoming packets to be encapsulated in the binary packet form */
		m_bRH_firstKexPacketFollows,
							/**< The first key exchange packet follows the algorithm negotiation
							packet */
		m_bIsSocketAlive,	/**< Boolean flag used to help calling classes/threads determine if
							the socket is still alive. Our Transport class will most likely
							query this to determine if the socket was closed or died. */
		m_bWasSocketDisconnected; /**< Boolean flag used to help the caller determine if the
							socket was disconnected unexpectedly. */

	EncType
		m_encryptionType;

	CryptoStuff
		*m_pCrypto;			/**< Object to help with diffe-hellman keyexchanges and anything
							else that's crypto-related. */

	Queue
		*m_pInboundQ;		/**< This queue holds full packets that have been read off the socket
							but have not yet been processed */

	pthread_mutex_t
		m_inboundQMutex,	/**< Mutex used to safeguard our m_inboundQ */
		*m_pActivityMutex,	/**< Mutex used in conjunction with m_activity_cv to help alert
							threads when activity is detected. 
							@\see PTssh::m_activity_cv	*/
		m_isAliveMutex;		/**< Mutex used to make setting/getting m_bIsSocketAlive thread safe */

	pthread_cond_t
		*m_pActivity_cv;	/**< This condition variable is used to help indicate activity.
							@see PTssh::m_activity_cv */

	SocketSend
		*m_pSS;				/**< Pointer to our socket send object. All packets that are to be
							sent get queued here and then sent out */
	SocketRecieve
		*m_pSR;				/**< Pointer to our socket recieve object. All incoming packets are
							read off the socket and put together in this thread. */
	Transport
		*m_pTransport;		/**< Pointer to our Transport class. The SocketSend class uses
							this so that it can query the window size for each channel */
	ChannelManager 
		*m_pChannelMgr;		/**< Pointer to our Channel Manager class. This is how we
							access all data on or related to a channel. We do not
							own this pointer so don't delete it! 
							TODO: make this pointer correctly constant. */
};

#endif
