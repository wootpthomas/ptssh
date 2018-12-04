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

#ifndef _PTSSH
#define _PTSSH

/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"
#include <pthread.h>
#include "PTsshLog.h"



/*************************
 * Forward Declarations
 ************************/
class Transport;
class ChannelManager;
class Data;
class LinkedList;
struct stat;

#ifdef PTSSH_SFTP
  class PTSftp;
#endif

/** \class PTssh
 * Paul Thomas's SSH main class.
 * This is the main class that abstracts all of SSH's abilities into
 * what should *hopefully* be a simple to use class based approach. The
 * Normal way to go about using PTssh to connect to a remote SSH server and then
 * authenticate with one of several methods. After you have been successfully
 * authenticated, you can then create channels and then make requests on each
 * channel to do things like create an interactive ssh client, forward a TCP/IP
 * connect, create a TCP/IP tunnel, run/startup a remote process, etc.
 */
class PTssh
{
public:

	/**********************************
	 * Public data types
	 **********************************/


	/**
	* When creating a channel, you specify the type of channel that you wish to create.
	*/
	enum ChannelType {
		CT_SESSION,		/**< Specifies the channel is of the generic "session" type */
		CT_DIRECT_TCPIP,	/**< The channel is a direct TCP/IP tunnel */
		CT_FORWARDED_TCPIP,/**< The channel is a forwarded TCP/IP connection. Think one-
						way tunnel */
		CT_X11				/**< The channel is a X11 channel */
	};



	/**********************************
	 * Main functions 
	 **********************************/

	/**
	 * Constructs a PTssh object.
	 * This constructor will initialize some of the PTssh internals. You must follow this
	 * function call up with a call to the PTssh::init() function to correctly allocate
	 * the rest of the internal data types needed by PTssh.
	 @see init
	 */
	PTssh();

	/**
	* PTssh destructor. This disconnects from the remote host if connected and
	* will free any resources used and kill PTssh. Its recommended that you close
	* any open channels before letting/making a PTssh object die. This way you can
	* "gracefully" close any open resources.
	* IF you do not close open channels on your own, PTssh will forcefully close any
	* open channels before shutting down internal threads and deleting any allocated
	* structures.
	*/
	~PTssh(void);

	/**
	* Initializes the PTssh class internals. After creating a new PTssh object, you should
	* then immediately call init to initialize the internal data structures.
	@param[in] username The username that is to be used for connecting with the SSH server
	@param[in] remoteHostAddress const char * to the remote host. This string can either
		be in IPv4 address (ex: 127.0.0.1) format or a more human readable URL
		form (ex: pssh.is.awesome.com)
	@param[in] remotePort unsigned 16-bit integer specifying the port to use for
		the SSH connection. Valid ranges are 0 - 65535
	@return Returns PTSSH_SUCCESS on success, or error code on failure
	*/
	int32 init(
		const char *username,
		const char *remoteHostAddress,
		uint16 remotePort = 22);

	/**
	* Gets a human readable string representing the version number for PTssh in this format:
	* <major>.<minor>.<patch> Build number: <integer> Build date: mm/dd/yyyy
	* Calling process takes ownership of the string and is responsible for its deletion!
	* Example version string:
	*    1.0.12 Build number 1234 Build date 8/12/2009
	@param[out] ppVerStr Pointer to a string pointer (Null terminated) that will hold a
		string representing PTssh's version information.
	@return Returns PTSSH_SUCCESS on success and the given pointer points to an
		allocated string holding version info.
	*/
	int32 getVersionInfo(char **ppVerStr);
	
	/**
	* This lets us change the log level so that we can either suppress or increase the
	* level of debugging messages. Available levels of logging are found in PTsshLog.h
	*/
	int32 setLogLevel(PTSSH_LogLevel level);

	/**
	* This will allow developers to provide their own function to appropriately redirect
	* PTssh's debugging messages to their own function. Their function must support the 
	* format: int printFunc(const char *, va_list)
	@see setLogLevel
	*/
	int32 setLogFunction( int (*pPrintFunc)(const char *, va_list) );

	/**
	* Sets the specified callback function. Ex: If you register a DISCONNECT callback
	* type, then when a socket disconnect occurs, PTssh will spin off a worker thread 
	* which will call the developer's pCallbackFunc function pointer. 
	* 
	* The pDeveloperData is a void pointer which will be inside the callback data that
	* will be passed to the pCallbackFunc function. The end developer can use it as
	* storage, PTssh does not touch it!
	* 
	* It's recommended that you setup a callback for the DISCONNECT event at the minimum.
	* You can still use the PTssh class just fine if you don't, but PTssh won't have any way
	* to inform you of errors when they happen besides eventually erroring out when you call a
	* function.
	* 
	* So for example, Let's say your code is C++ and you want to register a callback so that
	* you get informed if the socket gets disconnected. Create a static function (static functions
	* use the cdecl calling convention) and register it with PTssh
	\code
// C++ example, using PTssh class directly
static void ourCallBackFunc(struct PTsshCallBackData *pData)
{
   printf("Callback function called! Callback Data at 0x%X\n", pData);
   printf("Developer passed in data pointer 0x%X\n", pData->pDeveloperData);
   
   //Cast the our example data to a int pointer and dereference to get data
   printf("Data is %d\n", *(int*)pData->pDeveloperData);   //prints 1234
}

//.... Assuming you have a PTssh pointer -> pPTssh and its already connected
int exampleDeveloperData = 1234;

void main() {
//Normal PTssh setup....
// ....
//Register our callback function
pPTssh->setCallbackFunction(ET_DISCONNECT, &ourCallBackFunc, (void*)&exampleDeveloperData);
}
//ourCallBackFunc is now called if the socket experiences a disconnect!
\endcode

	@note If you wish to get rid of a callback function that was set, simply set the callback
	    function again but pass in NULL as the pointer to the callback function
	@param[in] type Specifies what type of callback event will call the callback function
	@param[in] pCallbackFunc A pointer to the function that you want to be called when
		the specified callback type occurs. If this is void, then you essentially clear
		the function pointer for the given callback. The function should be in the form:
		void func(struct PTsshCallBackData *);
	@return Returns true on success and false on failure
	*/
	bool setCallbackFunction(
		PTsshEventType eventType,
		void (*pCallbackFunc)(struct PTsshCallBackData *),
		void * pDeveloperData);

	/**
	* Gets the specified function pointer and call back data for the specified
	* event type */
	void (*getCallbackFunction(PTsshEventType eventType))(struct PTsshCallBackData *);

	/**
	* Gets the specified function pointer and call back data for the specified
	* event type */
	void * getCallbackData(PTsshEventType eventType);

	/**
	* Try and connect to remote host. 
	* This will try to create a socket and connection to the remote host. If it
	* succeeds, you can continue on and authenticate and create channels. If not,
	* check the return value.
	@return Returns PTSSH_SUCCESS on success, PTssh failure code otherwise
	*/
	int32 connectUp();

	/**
	* Disconnects from the remote SSH server. This will try and gracefully close
	* any open channels before disconnecting from the server. Disconnecting will allow
	* you to change the username and attempt to reconnect. It will act about the same as
	* if you just destroyed and created a new PTssh object.
	@return Returns true on success, false on failure
	@see closeChannel()
	*/
	int32 disconnect();

	/**
	* Gets a copy of the server's host key. Default format is an MD5 hash, otherwise
	* a SHA-1 Hash of the server's host key is returned.
	@param[out] ppBuf Pointer to a pointer that will be allocated with a buffer large
		enough to hold the server's host key
	@param[out] bufLen Length of the server's host key
	@param[in] bAsMD5_hash Boolen flag that determines if the hash returned is a MD5 or
		a SHA-1 hash of the server's host key
	@return Returns PTSSH_SUCCESS on success, otherwise an error code
	@note It's up to the caller to delete the pointer when its done with it!
	*/
	int32 getServerHostKey( uint8**ppBuf, uint32 &bufLen, bool bAsMD5_hash = true);

	/**
	* Checks to see if the specified authentication type is supported by the remote SSH server
	@param[in] authType The PTssh authentication type. Valid types are:
		PTsshAuth_None
		PTsshAuth_HostBased
		PTsshAuth_PublicKey
		PTsshAuth_Password
		PTsshAuth_KeyboardInteractive
	@param[out] bResult The answer to the question you seek! True if the specified auth method
		is supported, false if it is not.
	@return Returns PTSSH_SUCCESS if everything went ok, otherwise an error
	*/
	int32 isAuthSupported(PTsshAuthMethod authType, bool &bResult);

	///**
	//* Authenticates the user by public key found in the specified file
	//@param[in] String that holds the absolute path to the public key file
	//@return Returns PTSSH_SUCCESS on success, negative error number on failure
	//@see getRemoteHostAuthMethods()
	//@see isAuthPublicKeySupported()
	//@see getLastErrorMsg()
	//*/
	//int32 authByPublicKey(const char * absPathToPublicKeyFile);

	// PT: Leaving unimplemented, doesn't seem to really be used anymore
	/**
	* As per the SSH spec, users are allowed to query the server to see if
	* the given public key method is acceptable. 
	@param[in] pPublicKeyBlob64 A character buffer holding the public key which is encoded
		in base64 encoding
	@param[in] pPublicKeyBlob64Len The size of the public key buffer
	@param[in] pPrivateKeyBlob64 A character buffer holding the private key which is encoded
		in base64 encoding
	@param[in] pPrivateKeyBlob64Len The size of the private key buffer
	@param[in] passphrase Optional. The key password, if one was set when the key was created.
		PTssh will use this key to decrypt the public key before attempting authentication
	@param[out] bResult This is set to true if the given public key is allowed,
	    otherwise it will be set to false
	@return Returns PTSSH_SUCCESS on success, negative error number on failure
	*/
	int32 isPublicKeyAcceptable(
		bool &bResult,
		const char *pPublicKeyBlob64, 
		uint32 pPublicKeyBlob64Len,
		const char *pPrivateKeyBlob64,
		uint32 pPrivateKeyBlob64Len,
		const char *passphrase = NULL);

	/**
	* Authenticates the user by public key
	@note A few of you out there may ask why both public and private keys are required. This
		is because a signature is created from your private key and your public key is sent
		along so that the server can use it to verify the signature. In SSH clients, when you
		specify a "private key file", that file contains BOTH your public key and private key.
	@param[in] pPublicKeyBlob64 A character buffer holding the public key which is encoded
		in base64 encoding
	@param[in] pPublicKeyBlob64Len The size of the public key buffer
	@param[in] pPrivateKeyBlob64 A character buffer holding the private key which is encoded
		in base64 encoding
	@param[in] pPrivateKeyBlob64Len The size of the private key buffer
	@param[in] passphrase Optional. The key password, if one was set when the key was created.
		PTssh will use this key to decrypt the public key before attempting authentication
	@return Returns PTSSH_SUCCESS on success, netagive error number on failure
	@note This function only supports RSA keys. DSA/DSS is not yet fully implmented
	*/
	int32 authByPublicKey(
		const uint8 *pPublicKeyBlob64, 
		uint32 pPublicKeyBlob64Len,
		const uint8 *pPrivateKeyBlob64,
		uint32 pPrivateKeyBlob64Len, 
		const char *passphrase = NULL);

	/**
	* Authenticates the user by use of a password.
	@param[in] String which holds the user's current/new password.
	@param[in] Optional. String that holds the user's old password
	@return Returns:
		1 on success.
		2 if the response from the server requires that the user change their
			password. IF this is the case, then you can recall this function with
			the oldPassword field set to the old password and the password field
			set to the new password.
		0 on failure.
	* @see getRemoteHostAuthMethods()
	* @see isAuthPasswordSupported()
	* @see getLastErrorMsg()
	*/
	int32 authByPassword(const char * password, const char *oldPassword = NULL);

	/**
	* This does a keyboard interactive authentication. See RFC 4256 for more info.
	*
	NOT IMPLEMENTED YET
	int32 authByKeyboardInteractive();
	*/

	/**
	* Authenticates the user with the host-based method.
	NOT IMPLEMENTED YET
	* @return Returns true on success, false on failure
	* @see getRemoteHostAuthMethods()
	* @see isAuthHostBasedSupported()
	* @see getLastErrorMsg()
	*/
	int32 authByHost();

	/**********************************
	 * Channel Creation/Destruction
	 **********************************/
	/**
	* Creates a generic channel.
	* This is the type of channel to create for most operations like requesting a remote
	* shell, executing a command, etc. After the channel is created, you then use the 
	* channelRequest_* functions to then do specific operations.
	@param[out] cNum If the channel creation was successful, this variable is set to
		the new channel number.
	@return Returns 0 on failure and the channel number to refer to when specifying
		channel operations on success.
	@see channelRequest_pty()
	@see channelRequest_env()
	@see channelRequest_x11()
	@see channelRequest_shell()
	@see channelRequest_exec()
	@see channelRequest_windowChange()
	@see channelRequest_signal()
	@see channelRequest_exitStatus()
	@see channelRequest_exitSignal()
	*/
	int32 createChannel_session(uint32 &channelNumber);

	/**
	* The SSH RFCs refer to this type of port forwarding as TCP/IP forwarding. Simply
	* put, its a way for you to request that the SSH server you connect to, listen
	* on a given IP address and port number for incoming connections. When a connection
	* is recieved, that data is then forwarded from the SSH server (at the specified
	* IPAddr and port) to the client. Thus I like to call it remote port forwarding.
	* 
	* @note Even though you can make this request and it get accepted, nothing will happen
	* until something connects to that port. When an application connects on that server's
	* port, a channel is created and the client (think PTssh) is notified about the new
	* channel. Data will then come across the given channel and a remote tunnel is then
	* active.
	@param[in] pCallbackFunc Pointer to a cdecl calling convention function that will get
		called when something connects to the remote port forward that is being setup. This
		function MUST BE THREAD SAFE! Another thread will call it.
	@param[in] pCallbackData Pointer to a user-defined data item
	@param[in] IPAddr The IP address on the server that you want to listen for connections
		on. This is normally either "127.0.0.1" or an IP address of one of the servers
		network adapters. You can also specify "0.0.0.0" to listen on all adapters.
	@param[in] port The port number on the server that you want to listen on for incoming
		connections.
	@param[in] maxConnections This is the maximum number of simultaneous connections that
		PTssh will allow to connect up through the remote forwarding tunnel.
	@return Returns PTSSH_SUCCESS if the request was approved or an error number otherwise.
	@see createChannel_directTCPIP
	@see createChannel_AutomaticDirectTCPIP
	*/
	int32 requestRemotePortFowarding(
		void (*pCallbackFunc)(struct PTsshCallBackData*),
		void *pCallbackData,
		const char *IPAddr,
		uint16 port,
		uint32 maxConnections = 1);

	/**
	* This will cancel any remote port forwarding that was setup by a call to
	* requestRemotePortFowarding.
	@param[in] IPAddr The IP address on the server that you want to listen for connections
		on. This is normally either "127.0.0.1" or an IP address of one of the servers
		network adapters. You can also specify "0.0.0.0" to listen on all adapters.
	@param[in] port The port number on the server that you want to listen on for incoming
		connections.
	@return Returns PTSSH_SUCCESS on success or an error
	*/
	int32 cancelRemotePortFowarding(
		const char *IPAddr,
		uint16 port);

	/**
	* Opens a directed TCP/IP channel and sets the end developer's channelNumber variable
	* to the appropriate channel number to use for sending and receiving data. The end 
	* developer is responsible for forwarding data to and from the channel. 
	@param[out] cNum The channel number to use for sending and receiveing data.
	@param[in] destAddress Specifies address where the forwarded data ends up
	@param[in] destPort Specifies the port where the forwarded data ends up
	@param[in] sourcePort Specifies the source port where the forwarded data
		originated from
	@param[in] sourceIPAddress Specifies the source IP address where the forwarded
		data originated from.
	@return Returns PTSSH_SUCCESS on success, or a negative number indicating an error
		condition on failure. If successful, processes can now connect to the socket
		number localSocket and they will be "tunneled" over to destAddress and destPort.
	@see createChannel_directTCPIP_internalSocket
	*/
	int32 createChannel_directTCPIP(
		uint32 &cNum,
		const char *destAddress,
		uint16 destPort,
		const char *sourceIPAddress = "127.0.0.1",
		uint16 sourcePort = 22);

	/**
	* Opens a directed TCP/IP channel in which every aspect of tunneling is handled
	* internally by the library. PTssh will create the local socket to listen for
	* connections on and will accept connections and forward data from the channel
	* over the socket and forward data from the socket to the channel. Its highly
	* sugested that you provide a callback function pointer to a thread-safe function
	* that will get notified with various important events as they happen on the
	* tunnel. Currently, the only event that the callback function gets notified of
	* is when the tunnel closes either due to an error or a request to close.
	* When you want to close this directed TCP/IP tunnel, close it by specifying the
	* localSocket number that its listening on using the closeAutomaticDirectTCPIP
	* function.
	* \note 
	* All data to and from the socket is tunneled internally by PTssh. You will not
	* need to worry about servicing the listening socket in any way or worry about
	* reading from the channel this function creates.
	*
	* This is the lazy man's way to do tunneling ;p
	@param[in] localSocket Specifies the socket number on the local computer that other
		proccesses can connect to in order to use the direct TCP/IP "tunnel".
	@param[in] totalConnections Specifies the total number of connections that may be
		simultaneously connected to the tunnel at ancy given time. For security purposes
		you should keep this set at 1 unless you know that more are needed.
	@param[in] callbackFuncPtr Specifies a function that is to be called when certain
		events happen regarding directTCPIP events. Currently this function is not used
		but will likely be used in future versions of PTssh. For now, set this to NULL
	@param[in] destAddress Specifies address where the forwarded data ends up
	@param[in] destPort Specifies the port where the forwarded data ends up
	@param[in] sourcePort Specifies the source port where the forwarded data
		originated from
	@param[in] sourceIPAddress Specifies the source IP address where the forwarded
		data originated from.
	@return Returns PTSSH_SUCCESS on success, or a negative number indicating an error
		condition on failure. If successful, processes can now connect to the socket
		number localSocket and they will be "tunneled" over to destAddress and destPort.
	@see createChannel_directTCPIP
	@see closeAutomaticDirectTCPIP
	*/
	int32 createChannel_AutomaticDirectTCPIP(
		int localSocket,
		int totalConnections,
		int32 (*callbackFuncPtr)(void *ptrStorage),
		const char *destAddress,
		uint16 destPort,
		const char *sourceIPAddress,
		uint16 sourcePort);

	/**
	* When you are ready to stop tunneling that was setup via the 
	* createChannel_AutomaticDirectTCPIP
	* function call, you can stop listening for connections on the tunnel and close
	* any open tunnel thats already running for the associated localSocket
	@param[in] localSocket
	@return Returns PTSSH_SUCCESS if all good or a negative error on failure
	*/
	int32 closeAutomaticDirectTCPIP(
		int localSocket);

	/**
	* Closes an open channel. After calling close on a channel, all of its resources and
	* information will be freed from memory.
	@param[in] channelNumber channel number to close. If you do not specify a channel number
		all opened channels will be closed.
	@return Returns true if successful or false on a failure
	*/
	int32 closeChannel(
		uint32 channelNumber);

	/**********************************
	 * Channel Requests
	 **********************************/

	/**
	* Requests a Pseudo Terminal (PTY) on the remote host. In practice, this request
	* is normally followed by the shell request so that you can have a fully interactive
	* shell which is what most SSH clients do. Most of the time you'll likely only need to
	* call this function and specify channel number and type.
	* Zero dimension parameters are ignored. The character/row dimensions override the
	* pixel dimensions (when nonzero). 
	@param[in] channelNumber Specifies the channel to make the request on
	@param[in] terminalType Specifies the type of terminal to emulate. Ex: vt100,
		vt102, ansi, etc.
	@param[in] termCharWidth Optional, specifies the default width of the terminal in characters
	@param[in] termCharHeight Optional, specifies the default height of the terminal in characters
	@param[in] termPixWidth Optional, specifies the default width of the terminal in pixels
	@param[in] termPixHeight Optional, specifies the default height of the terminal in pixels
	@param[in] termModes Optional, specifies the encoding terminal modes as described in
		RFC 4254 (SSH-CONNECT) section 8.
	@param[in] termModesLength Required if the termModes parameter is used. This specifies the
		length of the termModes string since that string is not null terminated.
	@return Returns a positive number if the request was approved, 0 if
		the request was rejected, or a negative error code if some type of
		an error occured.
	*/
	int32 channelRequest_pty(
		uint32 channelNumber,
		const char * terminalType,
		uint32 termCharWidth = PTSSH_TERM_WIDTH,
		uint32 termCharHeight = PTSSH_TERM_WIDTH,
		uint32 termPixWidth = 0,
		uint32 termPixHeight = 0,
		const char * termModes = "");

	/**
	* Requests a shell on the specified channel. The shell that is executed will
	* be the user's default shell
	@param[in] channelNumber Specifies the channel to make the request on
	@return Returns a positive number if the request was approved, 0 if
		the request was rejected or a negative error code if some type of
		an error occured.
	*/
	int32 channelRequest_shell(	uint32 channelNumber);
	
	/**
	* Requests X11 forwarding on the specified channel. If you want PTssh to shuttle all
	* X11 traffic to your local X11 server, then do not specify a callback function pointer
	* or callback data. We will use our own methods and will shuttle data to/from the tunnel and
	* the local X11 server. PTssh assumes that the X11 server will be listening on port
	* 6000 and will attempt to connect any incoming X11 channel open requests to that
	* port. IF a X11 channel open request comes in and we can't connect to port 6000, then
	* the X11 channel open will be rejected.
	*
	* @note If you specify your own callback function pointer, make sure that function is thread
	* safe! The thread that calls the callback function will be a notification thread!
	*
	* @note Also, due to how X11 channel open notifications come in from the server, its
	* impossible for PTssh to determine which channel they originated from. 
	*
	@param[in] channelNumber Specifies the channel to make the request on
	@param[in] screenNumber Optional. The X11 screen number to use for the connection.
		Default = 10
	@param[in] bSingleConnectionOnly Optional. If true, only a single connection is allowed
		through the channel. Default = false
	@param[in] pCallbackFunc Optional. Specifies the callback function to run when a X11
		channel is opened. This function should be responsible for getting the channel
		number (which is inside the struct PTsshCallBackData) and tunneling the data to/from
		the channel to the X11 server.
	@param[in] pCallbackData Optional. A user-specified pointer which will be stored and
		made available in the struct PTsshCallBackData when the callback function is ran.
	@return Returns PTSSH_SUCCESS if the request was approved or a negative error code
		on failure
	*/
	int32 channelRequest_x11Forwarding(
		uint32 channelNumber,
		uint32 screenNumber = 0,
		bool bSingleConnectionOnly = false);

	///**
	//* This sets the callback function that will be called when a channel open request
	//* comes in from the server as a result of a X11 forward. IF this has never been
	//* set, PTssh will use its own internal X11 forwarding handler when a X11 connection
	//* is detected. The default behavior is to tunnel all traffic to the local X server.
	//* PTssh assumes that the X server is listening for connections on port 6000
	//*/
	//int32 setX11ChannelHandler(
	//	void (*pCallbackFunc)(struct PTsshCallBackData*) = NULL,
	//	void *pCallbackData = NULL);

	/**
	* Requests that the specified enviornment variable and value be set on the
	specified channel.
	@param[in] channelNumber Specifies the channel to make the request on
	@param[in] variableName Specifies the name of the environment variable
	@param[in] variableValue Specifies the value of the environment variable
	@return Returns a positive number if the request was approved, 0 if
		the request was rejected or a negative error code if some type of
		an error occured. Please note that if this fails, the remote server likely
		does not allow envr. variables to be set. Check the server's ssh config.
	*/
	int32 channelRequest_env(
		uint32 channelNumber,
		const char *variableName,
		const char *variableValue);

	/**
	* Requests that the server execute the specified command. The command string
	* may contain a path. As per the SSH spec, after this request is ran, the
	* channel will be shut down.
	* Note: After running a successful exec command, you'll normally get some data
	*   one the extended part of the channel and an End Of File.
	@param[in] channelNumber Specifies the channel to make the request on
	@param[in] commandToExecute Specifies the command to run. This can contain
		either a relative or absolute path in case you need to specify the exact
		location of the executable or command to run.
	@return Returns a positive number if the request was approved, 0 if
		the request was rejected or a negative error code if some type of
		an error occured.
	*/
	int32 channelRequest_exec(
		uint32 channelNumber,
		const char * commandToExecute);

	/*
	* Requests that the server start the specified sybsystem.
	*/
	int32 channelRequest_subsystem(
		uint32 channelNumber,
		const char *pSubsystemName);

	/**
	* Requests a window dimension change. This is used when you have a terminal on a
	* channel and you want to change the dimensions. Zero dimension parameters are
	* ignored. The character/row dimensions override the pixel dimensions (when nonzero). 
	@param[in] channelNumber Specifies the channel to make the request on
	@param[in] termCharWidth Optional, specifies the default width of the terminal in characters
	@param[in] termCharHeight Optional, specifies the default height of the terminal in characters
	@param[in] termPixWidth Optional, specifies the default width of the terminal in pixels
	@param[in] termPixHeight Optional, specifies the default height of the terminal in pixels
	@return Returns a positive number if the request was approved, 0 if
		the request was rejected or a negative error code if some type of
		an error occured.
	*/
	int32 channelRequest_windowChange(
		uint32 channelNumber,
		uint32 termCharWidth = PTSSH_TERM_WIDTH,
		uint32 termCharHeight = PTSSH_TERM_WIDTH,
		uint32 termPixWidth = 0,
		uint32 termPixHeight = 0);

	/* Flow control related
	bool channelRequest_XonXoff(); */

	/**
	 *	Sends a signal to the process running on the specified channel
	 *	@param[in] nChannelNumber Specifies the channel to make the request on
	 *	@param eSignalType
	 *	@return Returns a positive number if the request was approved, 0 if
	 *	the request was rejected or a negative error code if some type of
	 *	an error occured.
	 */
	int32 channelRequest_sendSignal(
		const uint32 &nChannelnumber,
		const PTsshChannelSignalType &eSignal);

	/**
	* When the command running at the other end terminates, the following
    * request can be sent to return the exit status of the command.
	@param[in] channelNumber Specifies the channel to make the request on
	@param[out] exitStatus The return status of the command
	@return Returns a positive number if the request was approved, 0 if
		the request was rejected or a negative error code if some type of
		an error occured.
	*/
	int32 channelRequest_exitStatus(
		uint32 channelNumber,
		uint32 &exitStatus);

	/**
	* The remote command may also terminate violently due to a signal.
    * Such a condition can be retrieved by the following request. A zero
    * 'exit_status' usually means that the command terminated successfully.
	@param[in] channelNumber Specifies the channel to make the request on
	@param[out] exitSignal The return signal on the channel.
	@return Returns a positive number if the request was approved, 0 if
		the request was rejected or a negative error code if some type of
		an error occured.
	*/
	int32 channelRequest_exitSignal(
		uint32 channelNumber,
		uint32 &exitSignal);

	/** 
	* Reads data from the specified channel number. You can also specify a non-zero
	* number for the stream to read from extended data on the channel.
	@param[in] channelNumber Specifies the channel to make the request on
	@param[in] ppBuf A pointer that points to a BinaryPacket which contains channel data
	@param[in] bIsBlockingRead Set this to true if you want your process to block for
	    data until data is received on the channel or the timeout period expires.
	@param[in] microsecTimeout Number of microseconds to block for. If you specify
	    a value of 0, this will block until data is received on the channel or 
		until an error occurs. Use this to give you "select-like" functionallity on
		a per-channel basis.
	@param[in] stream Optional. If set to 0 (default) a read request will only
		read from the normal data stream. If set to 1 then read requests will
		read from the extended part of the channel stream.
	@return Returns PTSSH_SUCCESS if all went ok, otherwise a negative error code
	    is returned.
	*/
	int32 channelRead(
		uint32 channelNumber,
		Data **ppBuf,
		bool bIsBlockingRead = true,
		uint32 microsecTimeout = 0,
		bool bExtendedData = false);

	/** 
	* Writes data to the specified channel number. You can also specify a non-zero
	* number for the stream to write to extended data on the channel.
	@param[in] channelNumber Specifies the channel to make the request on
	@param[in] buffer A pointer to a buffer containing the data to be written
	@param[in] bufferSize Specifies the size of the buffer
	@return Returns a positive number representing the number of bytes successfully
		written to the channel or a negative error code if some type of	error occured.
	*/
	int32 channelWrite(
		uint32 channelNumber,
		const char *pBuffer,
		uint32 bufferSize);

	/**
	* Returns the number of bytes that is the most efficient packet size to send
	* to the remote host. Writing only this number of bytes or less to a channelWrite()
	* will result in the most efficient packet sending because the underlying code
	* will be a lot less likely to need to break this packet up into multiple smaller
	* packets before finally compressing, encrypting and sending.
	@param[in] channelNumber Specifies the channel to make the request on
	@param[out] byteLength Number of bytes that is the optimal data size to send when
		writing data to this channel using channelWrite()
	*/
	int32 getOptimalDataSize(
		uint32 channelNumber,
		uint32 &byteLength);

	/**
	* Returns a boolean indicating if an End-Of-File has been detected on the channel.
	* As per the SSH spec; once this flag has been recieved, the channel is then shut
	* down.
	@param[in] channelNumber Specifies the channel number to test for EOF
	@param[out] bResult Holds the EOF status. True indicats that an EOF has been detected.
	@return Returns 0 on success, a negative number on error.
	*/
	int32 channelGetEOF(uint32 channelNumber, bool &bResult);

	/**
	* When any function fails, an attempt is made to put some sort of a meaningful error
	* message to help the developer figure out why something failed.
	@return Returns a string containing the error message. You take ownership of the string
		and must delete it when finished with it.
	*/
	//char * getLastErrorMsg();

#ifdef PTSSH_SFTP
	/**
	* This initializes a SFTP connection with the server. If this succeeds, then the server
	* supports SFTP and you can now call getSftpObj and use it to access the SFTP
	* functionallity of PTssh. A PTSftp object is thread safe and can be shared amoung 
	* multiple threads.
	@return Returns PTSSH_SUCCESS and a pointer to a PTSftp object on success, otherwise
		an error code on failure
	*/
	int32 initSFTP();

	/**
	* Returns a pointer to the active PTSftp object, provided that you've already called
	* initSFTP and gotten a success result.
	* PTssh owns the object.
	*/
	PTSftp * const getSftpObj();

	/**
	* Shuts down the SFTP object associated with this PTssh object
	*/
	int32 shutdownSftp();

#endif

	/*****************
	* Secure Copy related
	*****************/
#ifdef PTSSH_SCP
	/**
	* Sets up the remote end to recieve the specified file. After this function completes
	* successfully, you can then write the file data on the returned channel number. After
	* writing all of the file data, you must call scpSendFinish() to complete the send.
	@param[out] cNum Channel number to use to write the file data over
	@param[out] optimalSize For speed purposes, this is the maximum number of bytes that
		should be sent with each channel data write. Otherwise, PTssh will end up splitting
		the packet up into smaller packets in order to fulfill the requirements of the remote
		end's maximum packet size.
	@param[in] pRemoteFilePath The path of the file (including file name)
	@param[in] fileSizeInBytes A 64-bit number specifying the total number of bytes
		to be transfered
	@param[in] fileCreateFlags File permission flags (Unix like). For instance, 
		if you wanted to assign these permissions: rwxrwxrwx you would use
		0x1FF (which is the default)
	@return Returns PTSSH_SUCCESS or a negative number indicating failure
	@see scpSendFinish()
	*/
	int32 scpSendInit(
		uint32 &cNum,
		uint32 &optimalSize,
		const char *pRemoteFilePath,
		uint64 fileSizeInBytes,
		uint32 fileCreateFlags = 0x1FF);

	/**
	* Completes the scpSend command on the specified channel. Sends any close messages,
	* closes the channel and lets it be recycled for later use.
	* Note: some SSH servers limit the maximum number of open channels to around 10 or
	* so. So watch the number of channels you have open at once.
	@param[in] cNum Channel number that was returned with the scpSendInit function call
		when this scp connection was first created.
	*/
	int32 scpSendFinish(uint32 cNum);

	/**
	* Sets up the remote end to send us the specified file. After this function completes,
	* you can expect to begin recieving file data on the channel. The file will be completed
	* after we get an EOF.
	* Once this command completes and if if returns PTSSH_SUCCESS, you can begin reading
	* the file data with channelRead()
	@param[out] channelNumber Channel number to use to read the file data
	@param[out] fileSize A 64-bit number specifying the total file size to be transfered
	@param[in] pRemoteFilePath The path of the file (including fild name) to read from the remote
	@reutrn Returns PSS_SUCCESS on successful scp init
	@see channelRead
	*/
	int32 scpReceiveInit(
		uint32 &cNum,
		struct stat &fileInfo,
		const char *pRemoteFilePath);

	/**
	* Completes the scpSend command on the specified channel. Sends any close messages,
	* closes the channel and lets it be recycled for later use.
	*/
	int32 scpReceiveFinish(uint32 channelNumber);
#endif /* PTSSH_SCP */



	/**********************************
	 * Helper functions
	 **********************************/
	/**
	* Gets the username that this ssh connection will use for authentication
	* requests.
	@return Returns a const string pointer to the username.
	@see connect()
	*/
	const char * getUsername();

	/**
	* Gets the remote host's address that this ssh connection will use for
	* authentication requests.
	@return Returns a const string pointer to the host address string.
	@see connect()
	*/
	const char *getRemoteHostAddress();

	/**
	* Gets the remote host's port that this ssh connection will use for
	* authentication requests.
	@return Returns the port number this connection uses
	@see connect()
	*/
	uint16 getRemoteHostPort();

	///** 
	// * Returns the current remote SSH server address.
	// * 
	// * @return Sting containing the remote server address. You are responsible
	// * for deleting the char * when you are done with it.
	// * @see PTssh(const char *remoteHostAddress, uint16 remotePort = 22)
	// * @see getRemoteHostPort()
	// */
	//char * getRemoteHostAddress();

	///** 
	// * Returns the current remote SSH server port
	// * 
	// * @return Returns a 16-bit unsigned int representing the port number
	// * @see PTssh(const char *remoteAddress, uint16 remotePort = 22)
	// * @see getRemoteHostAddress()
	// */
	//uint16 getRemoteHostPort();


	/************************************
	* Handlers
	*************************************/
	/**
	* The default X11 handler will simply call this function. This is the actual function
	* that will take and create a threaded handler to transfer data between the local X11
	* server (if one is running) and our channel... an X11 tunnel.
	*/
	int32 handleX11Connection(uint32 channelNum);

	/**
	* Lets us query the connection status of this object
	*/
	bool isConnected() { return m_bIsConnected; }

	/**
	* Lets us query the authentication status of this object
	*/
	bool isAuthenticated() { return m_bAuthenticated; }

protected:
	/**
	* PTssh automatically calls this every time init() is called. The purpose is to determine if
	* a PTssh object being init'd is the very FIRST one. If it is and the platform is Windows, 
	* we need to initialize the Winsock stuff
	*/
	static int32 global_init();

	/**
	* If any of the isAuth_*_Supported functions are called and m_bDoWeHaveAuthMethods
	* is false, then this function will be called to retrieve the authentication methods.
	* @return Returns true if the authentication methods were successfully retrieved.
	*/
	bool getRemoteHostAuthMethods();
	
	/**
	* Sends an End-Of-File message on the specified channel. The end developer should not need
	* this, as they should be calling channelClose() and we send EOF if needed.
	*/
	int32 channelSendEOF(uint32 channelNum);

	/**
	* Gets the current SSH service type that we are operating in. Useful to see
	* if we need to send a service request message before we send something like
	* an authentication request. */
	int32 setServiceType( PTsshServiceType serviceType);

	/**
	* Gets the authentication methods allowed by the server 
	*/
	int32 getAuthMethods();

	char
		*m_pUsername,
		*m_pSSHServerAddr,
		*m_pAuthMethods;       /**< String returned from the server that tells us what authentication
							   methods the server allows */

	uint16
		m_serverPort;

#ifdef PTSSH_SFTP
	PTSftp
		*m_pSftp;             /**< Pointer to our internal SFTP object */
#endif

private:


	bool
		m_bIsConnected,			/**< If true, we have a connection to the remote ssh
								server */
		m_bIsInitialized,       /**< True if the PTssh object has been initialized */
		m_bAuthenticated,       /**< If true, the remote server has successfully authenticated
								us. */
		m_bDoWeHaveAuthMethods; /**< If true, we have already sucessfully queried 
								the remote ssh server for its supported authentication
								types */

	/*****************************
	* Error code related
	*****************************/
	//char *
	//	m_pLastErrorMsg;

	ChannelManager
		*m_pChannelMgr;			/**< Pointer to the ChannelManager. This gives us quick and
								thread-safe access to channel data. Transport will use this
								and create/delete channels as needed.
								We only use its methods for getting information about specific
								channels. */
	Transport
		*m_pTransport;			/**< This is the object that handles all data to and from
								the transport layer. Its mainly responsible for creating
								and connecting the socket to the remote host, sending and
								recieving data and encrypting and decrypting data to/from
								the socket as it travels */

	pthread_mutex_t
		m_activityMutex,		/**< Mutex used in conjunction with m_activity_cv to help alert
								threads when activity is detected. 
								@\see m_activity_cv
								*/
		m_TcpIpTunnelHandlerMutex,/**< Mutex used to make sure that the addition of TcpIp
								  tunnel handlers is added to the respecitve linked list 
								  in a thread-safe way */
		m_x11TunnelHandlerMutex;/**< Mutex used to make sure that the addition of X11
								  tunnel handlers is added to the respecitve linked list 
								  in a thread-safe way */

	pthread_cond_t
		m_activity_cv;			/**< This condition variable is used to help indicate activity.
								It is shared by:
								1) PTssh
								2) Transport, PTsshSocket
								3) SocketSend
								4) PshSocketRecieve
								When any of the 4 threads get activity they alert thread 2 which
								acts as the manager of all of our threads. For instance, when
								PshSocketRecieve decodes a packet and places it in the PTsshSocket
								inbound queue, it will use this CV to wake up the thread PTsshSocket
								lives in so that it can check inbound and outbound data queues for
								data to process in addition to checking to see if nay socket error
								has occured.
								\@see m_activityMutex
								*/

	PTsshServiceType
		m_serviceType;			/**< Helps us decide if we need to send a service request message
								before doing something like a password authentication or a
								new channel creation request. */

	LinkedList
		*m_pTcpIpHandlers,     /**< Holds a list of all of the TcpIp tunnel handlers that are active
								on this PTssh instance */
		*m_pX11Handlers;       /**< Holds a list of all of the X11 tunnel handlers that are active on
							   this PTssh instance */

	/** Callback stuff **/
	void
		(*m_pCallBackFunc_disconnect)(struct PTsshCallBackData *),
								/** This is the function pointer that gets called when the socket disconnects
								unexpectedly. The function will also have passed to it a pointer to a
								PTsshCallBackData structure which contains more details about the callback
								and also has pointers to the PTssh instance and a void pointer that the end-
								developer can set and use to point to their custom data... */
		*m_pDeveloperData_disconnect;
								/** This is the pointer that we allow the end developer to set which we will
								put in a PTsshCallBackData structure when we do the callback. That way they
								can save a pointer to an instance of their class or another data object */

	//void
	//	(*m_pX11CallbackHandler)(struct PTsshCallBackData*), /**<This is a function pointer which is set
	//							to the X11 callback function. Its purpose is to service channel
	//							open requests that have come into PTssh as a result of X11 forwading.
	//							If this has not been set by the user, PTssh will us its default internal
	//							handler to tunnel X11 traffic to/fom the local X11 server starting
	//							at port 6000
	//							*/
	//	*m_pX11CallbackData;    /**< The end-developer can set this pointer to anything they choose so
	//							that when their X11 handler is called, they have access to a pointer
	//							that they define. This is how a user can access their own data within
	//							the handler */
};

#endif 
