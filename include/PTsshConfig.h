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
#ifndef _PTSSHCONFIG
#define _PTSSHCONFIG


//#if defined(_MSC_VER)
//	#define WIN32
//#else
//	#define UNIX
//#endif

/** 
 * Typdefs to make our lives easier
 */
typedef char				int8;
typedef unsigned char		uint8;
typedef short				int16;
typedef unsigned short		uint16;
typedef int					int32;
typedef unsigned int		uint32;
typedef long long			int64;
typedef unsigned long long	uint64;

/*****************************************************
* #Defines
***********************************************/
#ifndef NULL
#  define NULL 0
#endif

/************************
* <START> PTssh Enable/Disable features
************************/
//#define PTSSH_STATISTICS              //If defined, statistics about bytes sent/received are logged
//#define PTSSH_ZLIB                    //Enable the plain ol' SSH spec zlib method
//#define PTSSH_ZLIB_OPENSSH            //Enable the OpenSSH Zlib method: zlib@openssh.com
#define PTSSH_SFTP                    //Enable SFTP v3 support for PTssh
#define PTSSH_SCP                     //Enable SCP support in PTssh
//#define PTSSH_MultiThreaded_AES_CTR //NOT YET IMPLEMENTED



/** Space saver!!
* If you do not need PTssh's logging/debugging messages, you can comment this line out.
* This will keep from building PTssh with debugging/logging strings and will drastically
* reduce the size of the code */
#define PTSSH_ENABLE_LOGGING

#ifdef PTSSH_ENABLE_LOGGING
#  define PTSSH_SHOW_CONNECTION_DETAILS //Prints out debugging info about the connection to remote SSH
#endif

/**
 * This will actually give PTssh a tiny performance boost. This will disable
 * the Nagle algorithm on the socket and force small keystrokes/packets
 * to go out immediately.
 */
#define PTSSH_TCP_NODELAY

/********************** Speed Optimization *******************************
 * Note: You will want to choose ONE of these #defines. This will directly effect
 * memory usage and read/write performance.
 ************************************************************************/
/*
 This is for those who demand the best possible performance, it will let the socket
 and our Sending and Recieving threads allocate a large amount of memory to be used
 for inbound/outbound buffers. It will also use deeper data queues so that we can
 aggressivlely cache data for sending and receiving. 
 Best used for 1000Mbps or faster networks. 
*/
#define PTSSH_Optimize_For_Speed_1000Mbps

/* This is a good middle-ground between performance and cpu usage. Applications that only
 * want to use a moderate amount of memory and still need fairly good speed over
 * 100Mbps links
 */
//#define PTSSH_Optimize_For_100Mbps

/* This keeps memory usage for buffers low and should provide adequate speed over 10Mbps
 * links, cable modems and that sort of link speed */
//#define PTSSH_Optimize_For_10Mbps

/* Buffers for inbound/outbound data are kept to a minimum. Low memory usage is 
 * most important. Some features of PTssh may not be turned on. This is probably
 * most suitable for enviornments. Where memory usage must be kept to a minimum
 * Note:
 *   You should probably also comment out PTSSH_ENABLE_LOGGING above! */
//#define PTSSH_Optimize_For_Low_Memory_Usage


/************************
* <END> PTssh Enable/Disable features
************************/


#ifdef PTSSH_SFTP
// I currently only support SFTP version 3
#  define PTSSH_HIGHEST_SUPPORTED_SFTP_VERSION 3
#endif


/***********************************************
* PTssh Internal Data sizes and optimization
***********************************************/
// Refs:
//http://www.ncsa.uiuc.edu/People/vwelch/net_perf/tcp_windows.html
//http://www.psc.edu/networking/projects/tcptune/
/* TODO: Make PTssh check these sizes on startup!
 * For example, specifying a max packet size larger than the Buf_out
 * size could put us in a situation that would keep us from sending
 * some packets */
#ifdef PTSSH_Optimize_For_Speed_1000Mbps
#   define PTSSH_DEFAULT_WINDOW_SIZE         0x400000  //4 MB
#   define PTSSH_SOCKET_SEND_BUF_SIZE        0x400000  //4 MB
#   define PTSSH_SOCKET_RECV_BUF_SIZE        0x400000  //4 MB
#   define PTSSH_MAX_RAW_BUF_IN_SIZE         0x400000  //4MB buffer
#   define PTSSH_MAX_RAW_BUF_OUT_SIZE        0x400000  //4MB buffer
#   define PTSSH_MAX_INBOUND_QUEUE_SIZE      0x800000  //8MB per channel max
#   define PTSSH_MAX_OUTBOUND_QUEUE_SIZE     0x800000  //8MB per channel max
#   define PTSSH_MAX_PACKET_SIZE             0x10000   //64KB
#elif defined PTSSH_Optimize_For_100Mbps
#   define PTSSH_DEFAULT_WINDOW_SIZE         0x100000  //1 MB
#   define PTSSH_SOCKET_SEND_BUF_SIZE        0x40000  //256 KB
#   define PTSSH_SOCKET_RECV_BUF_SIZE        0x40000  //256 KB
#   define PTSSH_MAX_RAW_BUF_IN_SIZE         0x40000  //256 KB
#   define PTSSH_MAX_RAW_BUF_OUT_SIZE        0x40000  //256 KB
#   define PTSSH_MAX_INBOUND_QUEUE_SIZE      0x100000 //1 MB per channel max
#   define PTSSH_MAX_OUTBOUND_QUEUE_SIZE     0x100000 //1 MB per channel max
#   define PTSSH_MAX_PACKET_SIZE             0x8000   //32KB
#elif defined PTSSH_Optimize_For_10Mbps
#   define PTSSH_DEFAULT_WINDOW_SIZE         0x80000  //512 KB
#   define PTSSH_SOCKET_SEND_BUF_SIZE        0x20000  //128 KB
#   define PTSSH_SOCKET_RECV_BUF_SIZE        0x20000  //128 KB
#   define PTSSH_MAX_RAW_BUF_IN_SIZE         0x20000  //128 KB
#   define PTSSH_MAX_RAW_BUF_OUT_SIZE        0x20000  //128 KB
#   define PTSSH_MAX_INBOUND_QUEUE_SIZE      0x80000  //512 KB per channel max
#   define PTSSH_MAX_OUTBOUND_QUEUE_SIZE     0x80000  //512 KB per channel max
#   define PTSSH_MAX_PACKET_SIZE             0x4000   //16KB
#elif defined PTSSH_Optimize_For_Low_Memory_Usage // defined PTSSH_Optimize_For_Low_Memory_Usage
#   define PTSSH_DEFAULT_WINDOW_SIZE         0x40000  //256 KB
#   define PTSSH_SOCKET_SEND_BUF_SIZE        0x10000  //64 KB
#   define PTSSH_SOCKET_RECV_BUF_SIZE        0x10000  //64 KB
#   define PTSSH_MAX_RAW_BUF_IN_SIZE         0x10000  //64 KB
#   define PTSSH_MAX_RAW_BUF_OUT_SIZE        0x10000  //64 KB
#   define PTSSH_MAX_INBOUND_QUEUE_SIZE      0x40000  //256 KB per channel max
#   define PTSSH_MAX_OUTBOUND_QUEUE_SIZE     0x40000  //256 KB per channel max
#   define PTSSH_MAX_PACKET_SIZE             0x1000   //4 KB
#else
# error "You need to uncomment one of PTssh's defines -> PTSSH_Optimize_For_..."
#endif

/* Ok, so I got a bit more creative with how the socketSend thread polls the
 * ChannelManager for data to send. It will start off at a small sleep time, and
 * the sleep time will increment as successive polls for packets come up empty.
 * The longer we go with not having anything to send, the longer we will sleep for.
 * However when we finally get something to send, we will immediately drop the
 * sleeping threshold back down to the minimum amount. */
#define PTSSH_SS_MIN_SOCKET_SLEEP_LENGTH    10   //Microseconds (0.001 msec)
#define PTSSH_SS_MAX_SOCKET_SLEEP_LENGTH    1000 //Microseconds (1.0 msec)

/* Following the same style as the SocketSend min and max sleep lengths, this
 * timing value is used in the SocketRecieve thread. We start off using the min
 * sleep length and progressively sleep longer and longer if no data is recieved
 * up until we hit our maximum threshold. As soon as we get data, we jump back
 * down to our minimum sleep time. This helps us get away from our dependency on
 * the Select() function */
#define PTSSH_SR_MIN_SOCKET_SLEEP_LENGTH    10   //Microseconds (0.001 msec)
#define PTSSH_SR_MAX_SOCKET_SLEEP_LENGTH    500 //Microseconds (0.5 msec)

/***********************
* PTssh Constants
***********************/
#define PTSSH_BAD_CHANNEL_NUMBER 0xFFFFFFFF
#define PTSSH_BAD_SOCKET_NUMBER 0xFFFFFFFF

#define PTSSH_SOCKET_BUF_LEN	1024 //Used in PTsshSocket for peeking at the Banner message
#define PTSSH_MAX_BLOCK_SIZE	16	//Used to create small temp buffers for decryption

#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
#  define PTSSH_COMP_TEMP_BUF_LEN 64  //Size used for initial inflation of zlib packets

/* Define this if you want to use a temp buffer for compressing packets and cut
 * down on memory allocations */
//# define PTSSH_COMP_USE_COMP_TEMP_BUF
#endif


/**< Specifies the maximum number of channels that a single PSSH object can 
manage. For efficiency and low memory usage, don't set this too high. The
max number of channels the SSH spec allows is equal to where a uint32 tops out */
#define PTSSH_MAX_CHANNELS			128

#define PTSSH_MAJOR_VERSION	0
#define PTSSH_MINOR_VERSION	3
#define PTSSH_PATCH_VERSION	0

#define PTSSH_BUILD_NUMBER 4
#define PTSSH_BUILD_DATE __DATE__

#define PTSSH_TERM_WIDTH  80
#define PTSSH_TERM_HEIGHT 25

#define PTSSH_BANNER "SSH-2.0-PTSSHv0.3 Pauls SSH class\r\n"

#define PTSSH_X11_AUTH_COOKIE_LEN 32



/***********************
Shutdown messages
***********************/
#define PTSSH_DisconnectMsg_NORMAL "PTssh disconnected normally"


/***********************
Error codes
***********************/
#define PTSSH_SUCCESS                                    0
#define PTSSH_ThreadShutDownNormally                     2
#define PTSSH_AlreadyAuthenticated                       3
#define PTSSH_ServerRequiresChangePassword               4
#define PTSSH_BannerMessageRecieved                      5
#define PTSSH_FAILURE									-1000
#define PTSSH_NOT_IMPLEMENTED                           -1001
#define PTSSH_ERR_NullPointer                           -1002
#define PTSSH_ERR_NullPointerGiven                      -1003

#define PTSSH_ERR_Could_not_resolve_remote_host_address  -1
#define PTSSH_ERR_Connection_refused                     -2
#define PTSSH_ERR_CouldNotQueuePacketForSending          -3
#define PTSSH_ERR_TransportObjectInitFailed              -4
#define PTSSH_ERR_CouldNotFindSpecifiedPacketType        -5
#define PTSSH_ERR_CouldNotGetRemoteBanner                -6
#define PTSSH_ERR_UnableToInitializeWinsockDLL           -7
#define PTSSH_ERR_CouldNotAllocateMemory                 -10
#define PTSSH_ERR_InvalidType                            -11
#define PTSSH_ERR_PacketMAC_failed                       -12
#define PTSSH_ERR_MaxChannelsReached                     -13
#define PTSSH_ERR_InvalidChannelNumber                   -14
#define PTSSH_ERR_ChannelRequestFailed                   -15
#define PTSSH_ERR_NoDataAvailable                        -16
#define PTSSH_ERR_CouldNotCreateTransportThread          -17
/***** Keyx errors *************/
#define PTSSH_ERR_CouldNotSetKeyExchangeType             -18
#define PTSSH_ERR_CouldNotCompute_E                      -19
#define PTSSH_ERR_CouldNotCreateBinaryPacket             -20
#define PTSSH_ERR_CouldQueuePacketForSending             -21
#define PTSSH_ERR_DidNotRecieve_SSH_MSG_KEXDH_REPLY      -22
#define PTSSH_ERR_CouldNotSet_K_S                        -23
#define PTSSH_ERR_CouldNotSetPublicKey                   -24
#define PTSSH_ERR_CouldNotSetSignatureOf_H               -25
#define PTSSH_ERR_CouldNotComputeSessionHash             -26
#define PTSSH_ERR_CouldNotVerifySignatureOf_H            -27
#define PTSSH_ERR_DidNotRecieve_SSH_MSG_NEWKEYS          -28
#define PTSSH_ERR_CouldNotParseHostKeyExchangePacket     -29
/****** Initial Socket connection errors *********/
#define PTSSH_ERR_CouldNotConnectToHost                  -40
#define PTSSH_ERR_CouldNotStartSocketSendThread          -41
#define PTSSH_ERR_CouldNotStartSocketRecieveThread       -42
#define PTSSH_ERR_CouldNotSetSocketBlocking              -43
#define PTSSH_ERR_CouldNotInit_SS                        -44
#define PTSSH_ERR_CouldNotInit_SR                        -45
#define PTSSH_ERR_CouldNotReadRemoteBanner               -46
#define PTSSH_ERR_CouldNotLookupHostName                 -47
#define PTSSH_ERR_CouldNotLookupIPAddress                -48
#define PTSSH_ERR_CouldNotBindSocket                     -49
#define PTSSH_ERR_CouldNotListenOnSocket                 -50
/******* Other errors**********************/
#define PTSSH_ERR_CouldNotInitializeChannelObject        -100
#define PTSSH_ERR_UnknownPublicKeyType                   -101
#define PTSSH_ERR_CouldNotQueuePacketForRecieving        -102
#define PTSSH_ERR_CouldNotStartupSCP                     -103
#define PTSSH_ERR_NotInitializedYet                      -104
#define PTSSH_ERR_ChannelIsClosed                        -105
#define PTSSH_ERR_CouldNotSendPacket_unknownType         -106
#define PTSSH_ERR_TriedToSplitNonChannelDataPacket       -107
#define PTSSH_ERR_YouMustCallPTssh_init                  -108
#define PTSSH_ERR_UnknownSignalType                      -109
#define PTSSH_ERR_SCPReceiveInitFailure                  -110
#define PTSSH_ERR_InvalidAuthenticationMethod            -111
#define PTSSH_ERR_ErrorCouldNotAuthenticate              -112
#define PTSSH_ERR_ReadPastEndOfBinaryPacket              -113
#define PTSSH_ERR_NoMatchingAutomaticDirectTCPIPFound    -114
#define PTSSH_ERR_AlreadyConnected                       -115
#define PTSSH_ERR_CallbackFunctionPointerCanNotBeNull    -116
#define PTSSH_ERR_CallbackDataNotFound                   -117
#define PTSSH_ERR_CallbackFunctionPointerWasNull         -118
#define PTSSH_ERR_ZlibInitFailed                         -119
#define PTSSH_ERR_ZlibCompressionFailure                 -120
#define PTSSH_ERR_SessionIDNotSet                        -121
#define PTSSH_ERR_ServerHostKeyIsNotYetSet               -122
#define PTSSH_ERR_NoAvailableAuthenticationMethod        -123
/******* Public key errors ****************/
#define PTSSH_ERR_InvalidPublicKeyType                   -130
#define PTSSH_ERR_InvalidBase64DecodeChar                -131
#define PTSSH_ERR_ZeroLengthPublicKey                    -132
#define PTSSH_ERR_ZeroLengthPrivateKey                   -133
#define PTSSH_ERR_BadRsaKey_N_NotEqual_P_times_Q         -134
#define PTSSH_ERR_BadRsaKey_P_lessThan_Q                 -135
#define PTSSH_ERR_BadRsaKey_iqmp_failed                  -136
#define PTSSH_ERR_RsaSigningFailure                      -137
#define PTSSH_ERR_UnknownKeyType                         -138

/******* PTsshSocket Errors ****************/
#define PTSSH_ERR_SocketDisconnectedUnexpectedly         -150






/******* Wrapper specific errors ****************/
#define PTSSH_ERR_InvalidObject                          -200

/******* SFTP specific errors ******************/
#define PTSSH_ERR_SftpVersionNotSupported                 -500
#define PTSSH_ERR_SftpBadPacketType                       -501
#define PTSFTP_E_UnexpectedResponse                       -502
#define PTSFTP_E_CouldNotGetResponse                      -503
#define PTSFTP_E_CouldNotCloseFile                        -504

#define PTSFTP_E_CouldNotFindMatchingRequestNode          -506
#define PTSFTP_E_CouldNotStartRequestMgrThread            -507
#define PTSFTP_E_GeneralError                             -508


//File permissions (octal)
# define FP_USR_R   0000400
# define FP_USR_W   0000200
# define FP_USR_X   0000100
# define FP_USR_RWX 0000700

# define FP_GRP_R   0000040
# define FP_GRP_W   0000020
# define FP_GRP_X   0000010
# define FP_GRP_RWX 0000070

# define FP_OTH_R   0000004
# define FP_OTH_W   0000002
# define FP_OTH_X   0000001
# define FP_OTH_RWX 0000007

//File types (octal)
#define FT_S_IFREG 0100000   //File
#define FT_S_IFDIR 0040000   //Directory

//File Open flags. These should match POSIX values
# define FO_CREATE      00100    /* creat file if it doesn't exist */
# define FO_EXCL        00200    /* exclusive use flag */
# define FO_TRUNC       01000    /* truncate flag */

/* File status flags for open() and fcntl().  POSIX Table 6-5. */
# define FO_APPEND       02000    /* set append mode */

/* File access modes for open() and fcntl().  POSIX Table 6-6. */
# define FO_RDONLY           0    /* open(name, O_RDONLY) opens read only */
# define FO_WRONLY           1    /* open(name, O_WRONLY) opens write only */
# define FO_RDWR             2


/***********************
* Function Callback stuff
***********************/
/**
* When registering a callback function with PTssh, you will need to specify
* which callback type belongs to what function. Ex: When a disconnect callback
* occurs, PTssh will immediately call the registered disconnect callback function
* if one was registered.
@note
Callback functions are not yet implmented and as a matter of fact, I'm still
debating on if I should put them in or not...
*/
enum PTsshEventType {
	ET_UNKNOWN = 0,
	//ET_DEBUG,      /**< Called for debugging */
	ET_DISCONNECT, /**< Called when the socket connection dies due to a disconnect */
	//ET_IGNORE,     /**< Not used */
	ET_MACERROR  /**< Called when we recieve a MAC (Message Authentication Code) error */
};

typedef void (*pPTsshCallBackFunc)(struct PTsshCallBackData *);

/* Forward class declaration for the struct */
class PTssh;

/**< When PTssh calls a function pointer to notify the end-developer about
* some event, we will always pass a pointer to a struct that contains data
* giving more details about the callback, why it happened and such. It also
* provides a means for the end-developer to store a custom pointer that their
* function can then use and reference when the callback occurs.
*/
struct PTsshCallBackData{
	PTssh
		*pPTsshObject;     /**< This will always point to the PTssh object that was responsible
							for calling the callback */
	PTsshEventType
		eventType;			/**< Type of event this callback is a result of */
	uint32
		channelNumber;
	void
		(*pCallBackFunc)(struct PTsshCallBackData *),
							/**< This is the function pointer that will be called when the callback
							occurs */
		*pDeveloperData;    /**< This is a user supplied data pointer. This way they can pass anything
							they wish in and have it later when the callback occurs */

	PTsshCallBackData(PTssh *pParent){
		pPTsshObject = pParent;
		pCallBackFunc = 0;
		pDeveloperData = 0;
		eventType = ET_UNKNOWN;
		channelNumber = PTSSH_BAD_CHANNEL_NUMBER;
	}
};




/***********************
* Linux socket error codes
***********************/
#  define EAGAIN          11

/***********************
* Log levels
***********************/
enum PTSSH_LogLevel{
   LL_silent = 0,    /**< Suppresses all print messages */
   LL_error = 1,         /**< Enables error messages when something messes up */
   LL_warning = 2,       /**< Enables non-critical warning messages */
   LL_info = 3,          /**< Enables informative messages (default) */
   LL_debug1 = 4,        /**< Enables basic debugging messages */
   LL_debug2 = 5,        /**< Enables more detailed debugging messages */
   LL_debug3 = 6,        /**< Enables very detailed debug messages */
   LL_debug4 = 7,        /**< Enables a crazy amount of debug messages */
};

/***********************
* Key exchange algorithms
***********************/
enum KEYX_Type{
	KEYX_dh_unknown = 0,
	KEYX_dh_group1_sha1 = 1,
	KEYX_dh_group14_sha1 = 2
};

/***********************
* Encryption Types
***********************/
enum EncType{
	ENC_invalid = 0,		
	ENC_none,           /**< no encryption; NOT RECOMMENDED */
	ENC_3des_cbc,       /**< Works: Three-key 3DES in CBC mode */
	ENC_des_cbc,        /**< One-key 3DES in CBC mode */
	ENC_blowfish_cbc,   /**< Works: Blowfish in CBC mode */
	ENC_twofish256_cbc, /**< Twofish in CBC mode, with a 256-bit key */
	ENC_twofish_cbc,    /**< Alias for "twofish256-cbc"
                        (this is being retained for historical reasons) */
	ENC_twofish192_cbc, /**< Twofish with a 192-bit key */
	ENC_twofish128_cbc, /**< Twofish with a 128-bit key */
	ENC_aes256_cbc,     /**< Works: AES in CBC mode, with a 256-bit key */
	ENC_aes192_cbc,     /**< Works: AES with a 192-bit key */
	ENC_aes128_cbc,     /**< Works: RECOMMENDED AES with a 128-bit key */
	ENC_serpent256_cbc, /**< Serpent in CBC mode, with a 256-bit key */
	ENC_serpent192_cbc, /**< Serpent with a 192-bit key */
	ENC_serpent128_cbc, /**< Serpent with a 128-bit key */
	ENC_arcfour,		/**< Works: the ARCFOUR stream cipher with a 128-bit key */
	ENC_idea_cbc,	    /**< IDEA in CBC mode */
	ENC_cast128_cbc,    /**< Works: CAST-128 in CBC mode */
	ENC_aes128_ctr,     /**< AES in CTR mode with a 256-bit key */
	ENC_aes192_ctr,     /**< AES in CTR mode with a 192-bit key */
	ENC_aes256_ctr,     /**< AES in CTR mode with a 128-bit key */
#ifdef PTSSH_MultiThreaded_AES_CTR
	ENC_MT_aes128_ctr,     /**< Multi-threaded AES in CTR mode with a 256-bit key */
	ENC_MT_aes192_ctr,     /**< Multi-threaded AES in CTR mode with a 192-bit key */
	ENC_MT_aes256_ctr,     /**< Multi-threaded AES in CTR mode with a 128-bit key */
#endif
};

/***********************
* Message Authentication Code (MAC algorithms)
***********************/
enum MAC_Type {
	MAC_invalid = 0,
	MAC_none,			/**< OPTIONAL no MAC; NOT RECOMMENDED */
	MAC_hmac_sha1,		/**< REQUIRED HMAC-SHA1 (digest length = key length = 20) */
	MAC_hmac_sha1_96,	/**< RECOMMENDED First 96 bits of HMAC-SHA1 (digest
								length = 12, key length = 20) */
	MAC_hmac_md5,		/**< OPTIONAL HMAC-MD5 (digest length = key length = 16) */
	MAC_hmac_md5_96		/**< OPTIONAL first 96 bits of HMAC-MD5 (digest
								length = 12, key length = 16) */
};

/***********************
* Host key algorithms
***********************/
enum HOST_Type{
	HOST_invalid = 0,
	HOST_none,
	HOST_rsa,
	HOST_dss
};

/***********************
* Compression algorithms
***********************/
enum COMP_Type{
	COMP_invalid = 0,
	COMP_none,
	COMP_zlib,
	COMP_zlib_openssh
};

/***********************
* Supported Algorithms
************************/
//more public key: diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1
#define PTSSH_KEYX_ALGORITHMS "diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
//#define PTSSH_ENC_ALGORITHMS "aes128-cbc,aes256-cbc,aes192-cbc,3des-cbc,blowfish-cbc,twofish256-cbc,twofish-cbc,twofish192-cbc,twofish128-cbc,serpent256-cbc,serpent192-cbc,serpent128-cbc,arcfour,idea-cbc,cast128-cbc,des-cbc,none"
//#define PTSSH_ENC_ALGORITHMS "aes256-ctr,aes192-ctr,aes128-ctr"
#define PTSSH_ENC_ALGORITHMS "aes128-cbc,aes256-cbc,aes192-cbc,3des-cbc,blowfish-cbc,arcfour,cast128-cbc,none"
#define PTSSH_MAC_ALGORITHMS "hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,none"
#define PTSSH_PUBKEY_ALGORITHMS "ssh-rsa,ssh-dss"


#if defined(PTSSH_ZLIB) && defined (PTSSH_ZLIB_OPENSSH)
#  define PTSSH_COMPRESSION_ALG "zlib@openssh.com,zlib,none"
#elif defined(PTSSH_ZLIB)
#  define PTSSH_COMPRESSION_ALG "zlib,none"
#elif defined (PTSSH_ZLIB_OPENSSH)
#  define PTSSH_COMPRESSION_ALG "zlib@openssh.com,none"
#else
#  define PTSSH_COMPRESSION_ALG "none"
#endif

#define PTSSH_LANGUAGES		""

/***********************
* Enums for Algorithm types
* The values in the enums are used internally in the PTsshSocket class! Do not modify
* them unless you know what you are doing!
************************/
enum ALG_Type {
	ALG_keyx = 0,			/**< Specifies key exchange algorithms */
	ALG_hostkey = 1,		/**< Specifies host key algs*/
	ALG_enc_CtoS = 2,		/**< Specifies encryption from client to server */
	ALG_enc_StoC = 3,		/**< Specifies encryption from server to client */
	ALG_mac_CtoS = 4,		/**< Specifies Message Authentication algs from client to server */
	ALG_mac_StoC = 5,		/**< Specifies Message Authentication algs from server to client */
	ALG_compress_CtoS = 6,	/**< Specifies compression algs from client to server */
	ALG_compress_StoC = 7,	/**< Specifies compression algs from server to client */
	ALG_lang_CtoS = 8,		/**< Specifies languages client to server */
	ALG_lang_StoC = 9		/**< Specifies languages server to client  */
};

/**
* Enums for SSH channel types
*/
enum PTsshChannelType {
	PTsshCT_session,
	PTsshCT_x11,
	PTsshCT_forwarded_tcpip,
	PTsshCT_direct_tcpip
};

/**
* PTsshChannel request types
*/
enum PTsshChannelRequestType{
	PTsshReq_tcpip_forward,
	PTsshReq_cancel_tcpip_forward,
	PTsshReq_pty,
	PTsshReq_env,
	PTsshReq_shell,
	PTsshReq_exec,
	PTsshReq_subsystem,
	PTsshReq_window_change,
	PTsshReq_xon_xoff,
	PTsshReq_signal,
	PTsshReq_exit_status,
	PTsshReq_exit_signal,
	PTsshReq_TOTAL				//Should only be used for allocating array size
};

/**
* Enums for allowed signals to send on a channel running a remote process
*/
enum PTsshChannelSignalType {
	Sig_ABRT,	/**< Abort signal */
	Sig_ALRM,	/**< Alarm signal */
	Sig_FPE,	
	Sig_HUP,
	Sig_ILL,
	Sig_INT,
	Sig_KILL,	/**< Kill signal: used for forcibly killing a process */
	Sig_PIPE,
	Sig_QUIT,	/**< Quit: used to tell a process to stop */
	Sig_SEGV,
	Sig_TERM,
	Sig_USR1,
	Sig_USR2
};


/**
* SSH service requests */
enum PTsshServiceType{
	PST_Unknown = 0,
	PST_UserAuth = 1,
	PST_Connection = 2
};

/**
* SSH public key types
*/
enum PTsshPublicKeyType {
	PKT_Unknown = 0,
	PKT_RSA = 1,
	PKT_DSS = 2
};

/**
* Authentication methods
*/
enum PTsshAuthMethod {
	PTsshAuth_None,
	PTsshAuth_HostBased,
	PTsshAuth_PublicKey,
	PTsshAuth_Password,
	PTsshAuth_KeyboardInteractive
};

/********************************
* Global strings
*********************************
In order to cut down on the number of strings that get included when PTssh is built, we
keep a global list of them so that instance can be shared between multiple classes. 
*/
static const char
	/***** Public Key types **********/
	*g_ssh_rsa = "ssh-rsa",
	*g_ssh_dss = "ssh-dss",
	/***** Compression types **********/
	*g_zlib = "zlib",
	*g_zlibOpenssh = "zlib@openssh.com",
	/***** HMAC types **********/
	*g_hmac_sha1 = "hmac-sha1",
	*g_hmac_sha1_96 = "hmac-sha1-96",
	*g_hmac_md5 = "hmac-md5",
	*g_hmac_md5_96 = "hmac-md5-96",
	/***** Key Exchange names **********/
	*g_diffie_hellman_group1_sha1 = "diffie-hellman-group1-sha1",
	*g_diffie_hellman_group14_sha1 = "diffie-hellman-group14-sha1",
	/***** Encryption Algorithm names **********/
	*g_3des_cbc = "3des-cbc",
	*g_des_cbc = "des-cbc",
	*g_blowfish_cbc = "blowfish-cbc",
	*g_twofish256_cbc = "twofish256-cbc",
	*g_twofish_cbc = "twofish-cbc",
	*g_twofish192_cbc = "twofish192-cbc",
	*g_twofish128_cbc = "twofish128-cbc",
	*g_aes256_cbc = "aes256-cbc",
	*g_aes192_cbc = "aes192-cbc",
	*g_aes128_cbc = "aes128-cbc",
	*g_serpent256_cbc = "serpent256-cbc",
	*g_serpent192_cbc = "serpent192-cbc",
	*g_serpent128_cbc = "serpent128-cbc",
	*g_arcfour = "arcfour",
	*g_idea_cbc = "idea-cbc",
	*g_cast128_cbc = "cast128-cbc",
#ifdef PTSSH_MultiThreaded_AES_CTR
	*g_mtAes128_ctr = "MT-aes128-ctr",
	*g_mtAes192_ctr = "MT-aes192-ctr",
	*g_mtAes256_ctr = "MT-aes256-ctr",
#else
	*g_aes128_ctr = "aes128-ctr",
	*g_aes192_ctr = "aes192-ctr",
	*g_aes256_ctr = "aes256-ctr",
#endif
	*g_none = "none";

#endif
