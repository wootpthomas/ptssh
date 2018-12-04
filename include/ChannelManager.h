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

#ifndef _CHANNELMANAGER
#define _CHANNELMANAGER

/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"

#include <pthread.h>
#include <semaphore.h>



/*************************
* Forward declarations
*************************/
class Channel;
class BinaryPacket;
class Queue;
class LinkedList;



/**
* The ChannelManager is responsible for providing thread-safe access to each of the
* respective channels and controls the creation and destruction of channels
*/
class ChannelManager
{
public:
	ChannelManager(void);
	~ChannelManager(void);

	/**
	* This will init all member variables.
	@return Returns true on success, false on failure
	*/
	int32 init();

	/** THREAD SAFE
	* When a new channel is needed, the calling class must first call this function so that
	* a new channel object can be created. The channel object stores items such as the channel
	* number and resource buffers used to store incoming packets
	@param[in] windowSize Sets the initial size of our local window in bytes
	@param[in] maxPacketSize Sets the maximum packet size we allow the remote host to send us
	@param[in] channelType Sets the type of channel this object represents
	@param[out] &channelNum Contains the local channel number. The user will need this to
		be able to reference which channel they want to do operations such as reads, writes,
		etc.
	@return Returns an integer representing the channel number if the request was successful.
		Otherwise, we return a negative number representing the error.
	*/
	int32 newChannel(
		uint32 windowSize, 
		uint32 maxPacketSize,
		PTsshChannelType channelType,
		uint32 &channelNum);

	/** THREAD SAFE
	* When a channel is no longer needed, this will free any resources associated with
	* that channel.
	@param channelNum Channel number to be deleted
	@param bSendCloseMsg In the case that a channel creation failed, setting this
		to true will keep us from sending a channel close request on a channel that
		was never successfully opened.
	@return Returns true on success, else false
	*/
	int32 deleteChannel( uint32 channelNum, bool bSendCloseMsg = true);

	/** THREAD SAFE
	* This function is expected to be called from PTssh.c. It will block the calling process
	* until we recieve the channel create result or until we get a socket error
	@param[in] channelNum Channel number to perform the operation on
	@return Returns PTSSH_SUCCES on success and a negative error code on failure
	*/
	int32 getChannelCreateResult(uint32 channelNum);

	/** THREAD SAFE
	* This function is expected to be called from the Transport process when it recieves
	* a result from a channel create request
	@param[in] channelNum Channel number to perform the operation on
	@param[in] bResult Flag indicating if the channel was created or not
	*/
	int32 setChannelCreateResult(uint32 channelNum, bool bResult);

	/** THREAD SAFE
	* Gets the result of the last channel request. This will block the calling process
	* until we recieve the result or until we get a socket error
	@param[in] channelNum Channel number to perform the operation on
	*/
	int32 getChannelRequestResult(uint32 channelNum);

	/** THREAD SAFE
	* Sets the result of the recieved channel request
	@param[in] channelNum Channel number to perform the operation on
	@param[in] bResult Result of the recieved channel request
	*/
	int32 setChannelRequestResult(uint32 channelNum, bool bResult);

	/** THREAD SAFE
	* Returns a boolean value indicating if the specified channel number is valid 
	*/
	bool isValidChannelNumber( uint32 channelNumber);

	/** THREAD SAFE
	* Checks the list of channels to see if we have a placeholder for forward-tcpip
	* (remote port forwarding). If so, we return true, else false 
	*/
	bool isValidRemotePortForward(const char *pHostAddr, uint16 port);

	/** Thread-safe
	* Normally the user's app will call down from its thread (that PTssh.h lives in) and
	* will get any available BP that are waiting in the queue. They can specify to read
	* from the extended error queue or even do a blocking read.
	@param[in] channelNum Channel number to perform the operation on
	@param[out] pData Double pointer that will recieve a pointer to a BP
	@param[in] bBlockingRead Set to true if you want the calling thread to block until
	   either data is recieved or an error occurs.
    @param[in] microsecTimeout Number of microseconds to block for. If you specify
	    a value of 0, this will block until data is received on the channel or 
		until an error occurs. Use this to give you "select-like" functionallity on
		a per-channel basis.
	*/
	int32 getInboundData(
		uint32 channelNumber,
		BinaryPacket **pData,
		bool bBlockingRead,
		uint32 microsecTimeout,
		bool bExtendedData);

	/** THREAD SAFE
	* When we recieve a channel data packet intended for this channel, this method
	* gets called to queue it in raw form. We refrain from any type of processing
	* so that we don't further burden the SocketRecieve  thread (which we are
	* running in).
	* This is meant to only be called by the SocketRecieve thread!
	@param[in] channelNum Channel number to perform the operation on
	*/
	int32 queueInboundData(
		uint32 channelNumber, 
		BinaryPacket *pBuf, 
		bool bIsExtendedData = false);

	/** THREAD SAFE
	* This is called to queue packets for sending to the remote server. This class will
	* respect the queue limit amount and will block any calling thread that tries to
	* add more data to the queue than we allow. The thread will block until there is more
	* room available or an error occurs.
	*/
	int32 queueOutboundData(
		BinaryPacket *pBP);

	/** THREAD SAFE
	* When we recieve a window adjust message for this channel, or we send channel
	* data to the remote server, we call this method to update our window size
	* counter. The number can be either + or -
	@param[in] channelNum Channel number to perform the operation on
	@param[in] bytesToAddOn A positive or negative number that will get added to
		the window size.
	*/
	int32 adjustWindowSizeRemote(uint32 channelNumber, int32 bytesToAddOn);

	/** THREAD SAFE
	* Sets the initial window size of the remote server based upon the
	* channel confirmation packet recieved.
	@param[in] channelNum Channel number to perform the operation on
	@param[in] size Initial window size
	*/
	int32 setInitialRemoteWindowSize(uint32 channelNumber, uint32 size);

	/** THREAD SAFE
	* When we send a window adjust message for this channel to the remote server,
	* or we recieve channel data from the remote server, we update our window size
	* counter. The number can be either + or -
	@param[in] channelNum Channel number to perform the operation on
	@param[in] bytesToAddOn A positive or negative number that will get added to
		the channel size.
	*/
	int32 adjustWindowSizeLocal(uint32 channelNumber, int32 bytesToAddOn);

	///** THREAD SAFE
	//* Returns the maximum packet size we can recieve
	//*/
	//uint32 getMaxPacketSizeLocal(uint32 channelNumber) { return PTSSH_MAX_PACKET_SIZE; }

	/** THREAD SAFE
	* Returns the maximum packet size we can send to the server
	@param[in] channelNum Channel number to perform the operation on
	@param[out] size The maximum number of bytes that a packet can hold as specified
		by the remote SSH server
	*/
	int32 getMaxPacketSizeRemote(uint32 channelNumber, uint32 &size);

	/** THREAD SAFE
	* Sets the maximum packet size we can send to the server
	@param[in] channelNum Channel number to perform the operation on
	@param[in] size Sets the maximum number of bytes that a packet can 
		hold as specified by the remote SSH server
	*/
	int32 setMaxPacketSizeRemote(uint32 channelNumber, uint32 size);

	/** THREAD SAFE
	* Gets the result of the channel's end of file status. This returns
	* true ONLY if an EOF packet has been recieved for this channel
	@param[in] channelNum Channel number to perform the operation on
	*/
	int32 getEOF(uint32 channelNum, bool &bResult);

	/** THREAD SAFE
	* Blocks until we recieve a End of file message for the channel or
	* until a socket error occurs
	@param[in] channelNum Channel number to perform the operation on
	*/
	int32 waitForEOF(uint32 channelNum);

	/** THREAD SAFE
	* Sets the result of the channel's end of file status. 
	@param[in] channelNum Channel number to perform the operation on
	*/
	int32 setEOF_recieved(uint32 channelNumber);

	/**
	* Gets the active status of the channel. Returns true if the channel
	* is still up and alive. Returns false if we have recieved a close
	* channel message
	@param[in] channelNum Channel number to perform the operation on
	@param[out] bResult True if the specified channel is open
	*/
	int32 isOpen(uint32 channelNumber, bool &bResult);

	/**
	* Returns true if we have already sent a channel close message for this
	* channel.
	@param[in] channelNum Channel number to perform the operation on
	@param[out] bResult True if we have already sent a channel close message
	*/
	int32 bAlreadySentCloseMsg(uint32 channelNumber, bool &bResult);

	/** THREAD SAFE
	* Blocks until we recieve a channel close message or until a socket
	* error occurs
	@param[in] channelNum Channel number to perform the operation on
	*/
	int32 waitForChannelClose(uint32 channelNumber);

	/** THREAD SAFE
	* Returns the remote channel number corresponding to this channel object.
	@param[in] channelNum Channel number to perform the operation on
	*/
	int32 getRemoteChannelNumber(uint32 localChannelNumber, uint32 &remoteChannelNum);

	/** THREAD SAFE
	* Sets the remote channel number corresponding to our local channel object.
	@param[in] channelNum Channel number to perform the operation on
	*/
	int32 setRemoteChannelNumber(uint32 localChannelNumber, uint32 remoteChannelNum);

	/** THREAD SAFE
	* Called to inform our channel manager that a channel is officially closed
	@param[in] channelNum Channel number to perform the operation on
	*/
	int32 setChannelCloseMsgReceived(uint32 channelNumber);

	/** THREAD SAFE
	* Sets the channel data for a forwarded-tcpip channel: IP address and port number.
	* This way when the remote server gets a connection on that IP and port and asks
	* to open a channel with us, we can reference our channels and see if we are
	* expecting a remote tunnel.
	@param[in] channelNum Local Channel number to perform the operation on
	@param[in] IPAddr String representing the IP address
	@param[in] port Port number we are listening on
	*/
	int32 setForwardedTcpIpData( uint32 cNum, const char *IPAddr, uint16 port);

	/** THREAD SAFE
	* Sets the channel data for a forwarded-tcpip channel: IP address and port number.
	@param[in] channelNum Local Channel number to perform the operation on
	@param[out] ppIPAddr Pointer to a string representing the IP address the remote server
		listens on for incoming connections to forward
	@param[out] port Port the remote server listens on for incoming connections
	@return Returns PTSSH_SUCCESS on success or an error otherwise.
	*/
	int32 getForwardedTcpIpData( uint32 cNum, char **ppIPAddr, uint16 &port);

	/** THREAD SAFE
	* Sets the cdecl function pointer that we will call when a remote port forward gets
	* a connection and we need to inform our end-developer about the new channel
	*/
	int32 setForwardNotifierCallbackData(uint32 cNum, struct PTsshCallBackData *pForwardData);

	/** THREAD SAFE
	* Returns the callback data with the associated remote port forward by looking up
	* the host address and port number
	*/
	int32 getForwardNotifierCallbackData(const char *IPAddr, uint16 port, struct PTsshCallBackData **ppForwardData);
	
	/**
	* Sets the X11 forwarding status for the specified channel
	*/
	int32 setX11ForwardStatus( uint32 cNum, bool bIsEnabled);

	/**
	* Gets the X11 forwarding status for the specified channel
	*/
	int32 getX11ForwardStatus( uint32 cNum, bool &bIsEnabled);

	/** THREAD SAFE
	* ONLY to be used by SocketSend
	*
	* Returns the next available packet for sending. This will take into account
	* the passed in maxTotalSize. If we are going to give up a channel data type
	* of packet, then we will also take into account the window space available
	* and will return a packet small enough to meet the requirements and the
	* PTSSH_SUCCESS return value. The packet will be automagickly split ;p
	* If no packet is available, then we will return PTSSH_NO_AVAILABLE_PACKETS. 
	* Upon some critical failure, we'll return an error code.
	@param[in] bIsInKeyXMode Flag that lets us know if the SocketSend thread is operating
	   in key exchange mode. If this is the case, we only look at the global queue and
	   will only return details about the first key exchange related packet in the queue.
	@param[out] maxTotalSize This is the maximum size of the packet that we have room
	   to send. In the case that its SSH channel data and its too big, we will split up
	   the packet provided that we can split the packet and create a packet small enough
	   to fit in the total space AND meet window space requirements for this channel.
	   Don't worry about MAC length, the SocketSend thread has adjusted maxTotalSize to
	   fit the currently use MAC.
    @return Returns PTSSH_SUCCESS if we have a packet that can be sent. Otherwise 
	   returns PTSSH_NO_AVAILABLE_PACKETS if we couldn't find any packets in the queue(s)
	   waiting to be sent. If we crapped out, we send an error message.
    */
	int32 getNextPacket(
		bool bIsInKeyXMode,
		uint32 maxTotalSize,
		BinaryPacket **ppBP);


private:

							/**< Array of pointers to active channel objects */
	Channel
		*m_pChannel[PTSSH_MAX_CHANNELS];

	Queue
		*m_pMainQ;			/**< All non-channel critical packets get placed into this
							main queue. This is mainly for global requests and such that
							could get "in front of" a packet that is associated with a
							SSH channel. */
	LinkedList
		*m_pQueueList;      /**< Linked list of queues that are active that may have data
							to send. We use this so that we can quickly iterate over the
							queues and find & return packets to be sent when the SocketSend
							class requests data */

	pthread_mutex_t				
		m_generalMutex;		/**< Mutex used to protect general queries to the m_pChannel
							object */
};

#endif
