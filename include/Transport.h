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

#ifndef _TRANSPORT
#define _TRANSPORT

/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"
#include "PTsshThread.h"

#include <pthread.h>
#include <semaphore.h>


/*************************
 * Forward Declarations
 ************************/
class ChannelManager;
class BinaryPacket;
class PTsshSocket;
class Queue;
class PTssh;


/**
* The transport class is used to help relay data to and from the SshSocket
* class and the PTssh class. When it gets requests from PTssh that require 
* replies, like a channel creation request, it will help send the request
* and only return with either the response or an indication of an error. If
* you've ever watched Office Space, this is the guy that takes the plans
* from the customers and gives them to the engineers.
* In that same respect, the Transport class ultimately knows (or cares)
* about SSH channels, the SshSocket class just gets the data from/to the 
* remote server. So when data comes in from the SshSocket class, it will
* deliver it to the appropriate channel. 
*
* For example, the user makes a channel X read request to PTssh. PTssh asks the
* Transport class to read from channel X. Transport will then check
* its data queue for that channel and report if there is data to be read.
* If a request that requires a response is sent, like a channel creation, then
* after the request is made, the caller (PTssh) will block on the channelCreate()
* call until Transport recieves a response or error and unblocks the function
* call.
*
* Transport operates in the context of its own thread so that it can be
* reading from or writing to the socket while PTssh is idle of user request.
* This is really nice because it allows the computational work of encryption
* and decryption to be on one CPU core while the user can read from channels
* or write to them and user resources from another CPU core... 2 or more core
* CPUS should benifit from this under heavy SSH traffic despite the encryption
* type used.
*
* To aide cross-platform stuff, I chose to use pthreads to provide a simple cross-
* platform threading library and still keep a small memory footprint. I may
* switch to Qt4 on request...
*/
class Transport: public PTsshThread
{
public:
	/**
	Creates a new Transport object.
	@param[in] pChannelMgr Pointer to our channel manager class. We us this to access
		channel related information
	@param[in] pActivityMutex Pointer to a mutex used to help with activity detection
	@param[in] pActivity_cv Pointer to a condition variable -> activity detection
	*/
	Transport(
		PTssh *pParent,
		ChannelManager *pChannelMgr,
		pthread_mutex_t *pActivityMutex,
		pthread_cond_t *pActivity_cv);

	/**
	Destructor. Make sure you stop this thread if its running so that it can
	cleanly disconnect from the remote host if its connected 
	*/
	~Transport(void);

	/**
	Initialized Transport and gets it all up and running in a thread and then
	creates any needed structures. 
	@param username Username to use for this connection
	@param remoteHostAddress IP address or fuly qualified domain name of the remote
		SSH server you want to connect to.
	@param remotePort Port to use for the SSH connection. Default of 22 will be used
		if no port number is speficied.
	@return Returns true if thread creation&startup went ok
	*/
	int32 init(
		const char *username,
		const char *remoteHostAddress,
		uint16 remotePort = 22);

	/**
	* Tries to connect to the remote SSH server, do diffe hellman key exchange
	* and get a working ssh connection. It will also attempt to resolve the IP address
	* or example.com domain passed into it. Make sure you called init() before attemping
	* to connect!
	@return Returns 0 on success, a negative number on an error... and maybe in the future
		something really cool!
	*/
	int32 connect();

	/**
	* Waits on a response to an authentication request. This will block the calling thread
	* until either we get a response or we get a socket error 
	*/
	int32 getAuthResult();

	/**
	* Waits on a response to a global request. This is normally used with forward-tcpip
	*/
	int32 getGlobalRequestResult();

	/**
	* Sends the message contained in the given BinaryPacket to the remote host. The packet
	* is first queued for sending. Under the hood, the packet will be asynchronously encrypted
	* and then sent over the socket. This function takes ownership of the pointer.
	*/
	int32 queueForSending(BinaryPacket *pBP);

	/**
	* This will block until a service result is available. Either by socket error,
	* or a valid result. Acquires the semaphore, gets result and releases.
	*/
	int32 getServiceResult();

	/**
	* Returns a copy of the allowed auth types string as read from the server
	*/
	char * getAllowedAuthTypes();

	/**
	* Creates a signature over the given data. Calls PTsshSocket to do the signature
	* creation.
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

protected:
	

private:
	/************************
	* Private Functions
	*************************/

	/**
	This is the function that the context of our thread will run on. The
	classes "event loop" essentially lives here.
	*/
	void run();

	/**
	* This takes a look at inbound packets and places them in the proper buffers to
	* wait on the user to ask for them. IF we detect a close socket request, then
	* we set bKeepProcessing to true before returning.
	*/
	void processInboundData(bool &bKeepProcessing);

	/**
	* Called when our thread is shutting down either by request or from a critical error.
	* This will release any blocked processes and cleanup resources */
	void cleanupAfterShutdown();


	/*************************
	* Packet handlers
	*************************/
	/**
	This function handles all SSH Disconnect messages
	@param[in] pBP A pointer to a binary packet
	*/
	void handleDisconnect( BinaryPacket * const pBP);
	
	/**
	This function handles all SSH Service response messages
	@param[in] pBP A pointer to a binary packet
	*/
	void handleServiceAccept( BinaryPacket * const pBP);

	/**
	This function handles channel open requests from the server. So far the only type of
	open request should come if we have requested remote port forwarding. When this happens
	we create a channel to handle the open request and then call the channel's informing
	function. This is simply a callback to a user specific function. We will spin off a
	thread seperate from the one that our transport class lives in so that we don;t slow down
	any processing. Then that spun-off thread will call the user's callback function to
	let them know about the channel open request. */
	void handleChannelOpenRequest(BinaryPacket * const pBP);

	/***********************
	* Private Enums
	************************/
	/**
	* MutexType provides an easy way to quickly reference the corresponding mutex and condition
	* variable in our m_blockers and m_condVars arrays (respectfully). They help us coordinate
	* our calling thread with our Transport thread so that we can send a SSH message
	* and block the calling thread until a response has been fully recieved and processed.
	*/
	enum MutexType {
		MT_general,
		MT_sockConnectionRelated,	/**< This mutex is used to block the calling function
										that called the connectUp() function until this 
										class is fully up and running. Also helps block 
										the calling process until we finish the keyexchange
										or a disconnect message is recieved. */
		MT_authResponse,			/**< Mutex used to release a calling thread's authentication
										request. We will only release the lock when we get a response
										or an error occurs. */
		MT_serviceRequestResponse ,	/**< Blocks the calling process until we get either a response to
										the service request or an error */
		MT_globalRequestResponse,   /**< Blocks the calling process until we get either a response to
										a global request or an error */
		MT_TOTAL_BLOCK_TYPES		/**< Only used to keep track of the total block types. This should
										NOT be used as a blocking semaphore index reference */
	};

	///**
	//* MutexType provides an easy way to quickly reference the corresponding
	//* mutex depending on why you are locking shizz */
	//enum MutexType {

	//	MT_TOTAL_MUTEX_TYPES = 3		/**< Only used to keep track of the total mutex types. This should
	//									NOT be used as a mutex index reference */
	//};

	/************************
	* Private Variables - PThreads related
	*************************/
	pthread_t
		m_thread;				/**< This is the thread that will make this class
								be able to be so awesome-0 */

	pthread_attr_t
		m_threadAttributes;		/**< Specifies attributes for the thread that makes
								Transport so sexy. */
	pthread_mutex_t
		m_mutexOutboundQ,		/**< Mutex responsible for providing thread-safe access
								to the outbound queue. All packets to be sent are placed in
								here. */
		m_mutexInboundQ,		/**< Mutex responsible for providing thread-safe access
								to the inbound queue. */
		m_mutexGeneralLock,		/**< Mutex responsible for providing thread-safe access
								to all general data */
		m_blockers[MT_TOTAL_BLOCK_TYPES],
		*m_pActivityMutex;		/**< Mutex used in conjunction with m_activity_cv to help alert
								threads when activity is detected. 
								@\see PTssh::m_activity_cv	*/

	pthread_cond_t
		m_condVars[MT_TOTAL_BLOCK_TYPES],
		*m_pActivity_cv;		/**< This condition variable is used to help indicate activity.
								@see PTssh::m_activity_cv */
		

	/************************
	* Private Variables
	*************************/
	ChannelManager 
		* const m_pChannelMgr;	/**< Pointer to our Channel Manager class. This is how we
								access all data on or related to a channel. We do not
								own this pointer so don't delete it!  */
	PTsshSocket
		* m_pSocket;			/**< Socket class to abstract all creation, sending, recieving,
								encryption/decryption, keyexchange and all that fun stuff */
	PTssh
		* const m_pPTssh;		/**< Pointer to our parent. Used in data for callback functions */


	bool
		m_bServiceResponse,		/**< Holds the result of the last service request */
		m_bChannelCreateResponse,/**< Holds the result of the last channel create request */
		m_bConnected,			/**< Flag used to tell if we are connected or not. This is 
								safe-guarded by MT_disconnect*/
		m_bPartialAuthSuccess;  /**< Flag representing the last bit of data from a partially
								failed authentication request */

	char
		*m_pUsername,			/**< Holds the username to use for this ssh session */
		*m_pRemoteHostAddress,	/**< Holds the IP address or domain address of the ssh
								server we will try and connect to */
		*m_pAllowedAuthTypes;   /**< Holds the string of allowed auth types */

	uint16
		m_remotePort;

	int32
		m_connectResponse,		/**< Stores the result of the connect call return value. See
								we will startup the thread and the calling function sits and
								waits till we release the m_semDoneConnecting semaphore. We
								only release that sem. when we have a connection result value
								in this variable. */
		m_serviceResponse,		/**< Stores the response of the service request */
		m_authResponse,			/**< Holds the result of the last authentication request */
		m_globalRequestResponse;/**< Holds the result of the last global request response */

	Queue
		*m_pOutboundQ,			/**< Queue for outbound packets. This is just a linked list
								of pointers to other BinaryPackets waiting to be encrypted
								and sent to the remote host*/
		*m_pInboundQ;			/**< Queue for inbound packets. This is just a linked list
								of pointers to other BinaryPackets */



};

#endif
