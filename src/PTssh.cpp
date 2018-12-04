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
#include "PTssh.h"
#include "Transport.h"
#include "ChannelManager.h"
#include "Data.h"
#include "BinaryPacket.h"
#include "SSH2Types.h"
#include "Utility.h"
#include "LinkedList.h"
#include "TcpIpTunnelHandler.h"
#include "X11TunnelHandler.h"
#include "PTSftp.h"
#include "PTsshLog.h"

#ifdef PTSSH_SFTP
#  include "PTSftp.h"
#endif

#if defined(WIN32)
#  define snprintf _snprintf
#  if defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
#    define _CRTDBG_MAP_ALLOC
#    include <stdlib.h>
#    include <crtdbg.h>
#    define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#    define new DEBUG_NEW
#  endif
#endif

#ifdef WIN32
	#include "Winsock2.h"
#endif


#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>




///////////////////////////////////////////////////////////////////////////////
PTssh::PTssh(void):
//m_pLastErrorMsg(NULL),
m_bIsConnected(false),
m_bIsInitialized(false),
m_bAuthenticated(false),
m_bDoWeHaveAuthMethods(false),
m_pUsername(NULL),
m_pSSHServerAddr(NULL),
m_serverPort(0),
m_pAuthMethods(NULL),
m_serviceType(PST_Unknown),
m_pChannelMgr(NULL),
#ifdef PTSSH_SFTP
   m_pSftp(NULL),
#endif
m_pTransport(NULL),
m_pTcpIpHandlers(NULL),
m_pX11Handlers(NULL),
m_pCallBackFunc_disconnect(NULL),
m_pDeveloperData_disconnect(NULL)
{


}

///////////////////////////////////////////////////////////////////////////////
PTssh::~PTssh(void)
{
	//Shutdown our SFTP object
#ifdef PTSSH_SFTP
	if ( m_pSftp)
	{
		shutdownSftp();
	}
#endif

	//If we haven't gracefully shutdown, do it now
	if ( m_bIsConnected)
		disconnect();

	if ( m_pTcpIpHandlers )
	{
		while( m_pTcpIpHandlers->size() )
			delete (TcpIpTunnelHandler*)m_pTcpIpHandlers->removeFirst();

		delete m_pTcpIpHandlers;
		m_pTcpIpHandlers = NULL;
	}

	if ( m_pX11Handlers )
	{
		while( m_pX11Handlers->size() )
			delete (X11TunnelHandler*)m_pX11Handlers->removeFirst();

		delete m_pX11Handlers;
		m_pX11Handlers = NULL;
	}

	if ( m_pTransport)
	{
		if (m_pTransport->isRunning())
			m_pTransport->stopThread();

		delete m_pTransport;
		m_pTransport = NULL;
	}

	if ( m_pChannelMgr)
	{
		delete m_pChannelMgr;
		m_pChannelMgr = NULL;
	}

	if ( m_pUsername)   
		delete m_pUsername;

	if ( m_pSSHServerAddr)
		delete m_pSSHServerAddr;

	if ( m_pAuthMethods)
		delete m_pAuthMethods;

	pthread_mutex_destroy( &m_activityMutex);
	pthread_mutex_destroy( &m_TcpIpTunnelHandlerMutex);
	pthread_mutex_destroy( &m_x11TunnelHandlerMutex);
	pthread_cond_destroy( &m_activity_cv);
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::init(
		const char *username,
		const char *remoteHostAddress,
		uint16 remotePort)
{
	int32 result = PTSSH_SUCCESS;

#ifdef WIN32
	//Initialize the Winsock DLL
	WSADATA wsadata;
	int sResult = WSAStartup(WINSOCK_VERSION, &wsadata);
	if (sResult)
	{
		PTLOG((LL_error, "Error initializing the windows socket DLL\n"));
		return PTSSH_ERR_UnableToInitializeWinsockDLL;
	}
#endif

	//Set our default print function for logging
	setLogFunction( &vprintf);

	m_serverPort = remotePort;
	m_pUsername = strdup(username);
	m_pSSHServerAddr = strdup(remoteHostAddress);

	if ( (! m_pUsername) || (! m_pSSHServerAddr))
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

	if ( pthread_mutex_init( &m_activityMutex, 0) != 0)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

	if ( pthread_mutex_init( &m_TcpIpTunnelHandlerMutex, 0) != 0)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

	if ( pthread_mutex_init( &m_x11TunnelHandlerMutex, 0) != 0)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

	if ( pthread_cond_init( &m_activity_cv, 0) != 0)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

	m_pChannelMgr = new ChannelManager( );
	if ( ! m_pChannelMgr || m_pChannelMgr->init() != PTSSH_SUCCESS)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

	m_pTransport = new Transport(this, m_pChannelMgr, &m_activityMutex, &m_activity_cv);
	if ( ! m_pTransport)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

	m_pTcpIpHandlers = new LinkedList();
	if ( ! m_pTcpIpHandlers)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

	m_pX11Handlers = new LinkedList();
	if ( ! m_pX11Handlers)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

	m_bIsInitialized = true;
	return result;

error:
	if ( m_pUsername )
		delete m_pUsername;
	if ( m_pSSHServerAddr )
		delete m_pSSHServerAddr;
	if ( m_pTransport )
		delete m_pTransport;

	if ( m_pChannelMgr)
		delete m_pChannelMgr;

	if ( m_pTcpIpHandlers )
		delete m_pTcpIpHandlers;

	if ( m_pX11Handlers )
		delete m_pX11Handlers;

	pthread_mutex_destroy( &m_TcpIpTunnelHandlerMutex);
	pthread_mutex_destroy( &m_x11TunnelHandlerMutex);
	pthread_mutex_destroy( &m_activityMutex);
	pthread_cond_destroy( &m_activity_cv);

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32 
PTssh::getVersionInfo(char **ppVerStr)
{
	*ppVerStr = new char[1024];
	if ( *ppVerStr)
	{
		memset(*ppVerStr, 0x0, 1024);
		// <major>.<minor>.<patch> Build number: <integer> Build date: mm/dd/yyyy
		sprintf(*ppVerStr, "%d.%d.%d Build number: %d Build date: %s",
			PTSSH_MAJOR_VERSION,
			PTSSH_MINOR_VERSION,
			PTSSH_PATCH_VERSION,
			PTSSH_BUILD_NUMBER,
			PTSSH_BUILD_DATE);
		return PTSSH_SUCCESS;
	}

	return PTSSH_ERR_CouldNotAllocateMemory;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::setLogLevel(PTSSH_LogLevel level)
{
	if (level >= LL_silent)
	{
		g_logLevel = level;
		return PTSSH_SUCCESS;
	}
	
	return PTSSH_FAILURE;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::setLogFunction( int (*pPrintFunc)(const char *, va_list) )
{
	if ( pPrintFunc)
	{
		g_printFunc = pPrintFunc;
		return PTSSH_SUCCESS;
	}

	return PTSSH_FAILURE;
}

///////////////////////////////////////////////////////////////////////////////
bool 
PTssh::setCallbackFunction(
		PTsshEventType eventType,
		void (*pCallbackFunc)(struct PTsshCallBackData *),
		void * pDeveloperData)
{
	switch( eventType) {
	case ET_DISCONNECT:
		m_pCallBackFunc_disconnect = pCallbackFunc;
		m_pDeveloperData_disconnect = pDeveloperData;
		break;
	case ET_MACERROR:
	default:
		return false;
	}

	return true;
}

///////////////////////////////////////////////////////////////////////////////
void
(*PTssh::getCallbackFunction(PTsshEventType eventType))(struct PTsshCallBackData *)
{
	switch( eventType) {
	case ET_DISCONNECT:
		return m_pCallBackFunc_disconnect;
		break;
	case ET_MACERROR:
	default:
		break;
	}

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
void * 
PTssh::getCallbackData(PTsshEventType eventType)
{
	switch( eventType) {
	case ET_DISCONNECT:
		return m_pDeveloperData_disconnect;
		break;
	case ET_MACERROR:
	default:
		break;
	}

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
const char * 
PTssh::getUsername()
{
	if ( m_pUsername && strlen(m_pUsername) > 0)
		return (const char*)m_pUsername;

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
const char * 
PTssh::getRemoteHostAddress()
{
	if ( m_pSSHServerAddr && strlen(m_pSSHServerAddr) > 0)
		return (const char*)m_pSSHServerAddr;

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
uint16
PTssh::getRemoteHostPort()
{
	return m_serverPort;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::connectUp()
{
	int32 result;

	if ( m_bIsConnected)
		return PTSSH_ERR_AlreadyConnected;

	if ( m_pTransport)
	{
		if ( m_pTransport->init(m_pUsername, m_pSSHServerAddr, m_serverPort) != PTSSH_SUCCESS)
			return PTSSH_ERR_TransportObjectInitFailed;
	}
	else
		return PTSSH_ERR_YouMustCallPTssh_init;

	result = m_pTransport->connect();
	if ( result == PTSSH_SUCCESS)
		m_bIsConnected = true;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::disconnect()
{
	const char
		*pDesc = PTSSH_DisconnectMsg_NORMAL;
	char
		*pLang = NULL;

	uint32 
		len =
		1 +					//byte      SSH_MSG_DISCONNECT
		4 +					//uint32    reason code
		4 + (uint32)strlen(pDesc) + //string    description in ISO-10646 UTF-8 encoding [RFC3629]
		4 + 0;              //string    language tag [RFC3066]
	int32
		result = PTSSH_SUCCESS;
	TcpIpTunnelHandler 
		*pTcpH = NULL;
	X11TunnelHandler
		*pX11 = NULL;

	//Shut down any TcpIp handler threads that may be running
	pthread_mutex_lock( &m_TcpIpTunnelHandlerMutex);
		while ( pTcpH = (TcpIpTunnelHandler*)m_pTcpIpHandlers->removeFirst() )
		{
			pTcpH->shutdown();
			delete pTcpH;
			pTcpH = NULL;
		}
	pthread_mutex_unlock( &m_TcpIpTunnelHandlerMutex);

	//Shut down any X11 handler threads that may be running
	pthread_mutex_lock( &m_x11TunnelHandlerMutex);
		while ( pX11 = (X11TunnelHandler*)m_pX11Handlers->removeFirst() )
		{
			pX11->shutdown();
			delete pX11;
			pX11 = NULL;
		}
	pthread_mutex_unlock( &m_x11TunnelHandlerMutex);

	//IF the transport thread is still running, close any channels that are left running
	if ( m_pTransport->isRunning() )
	{
		//Send a channel close message to all active channels
		for (uint32 cNum = 0; cNum < PTSSH_MAX_CHANNELS; cNum++)
		{
			if ( m_pChannelMgr && m_pChannelMgr->isValidChannelNumber(cNum))
			{
				result = closeChannel(cNum);
				if ( result != PTSSH_SUCCESS)
				{
					PTLOG((LL_error, "[PTssh] Error closing channel %d\n", cNum));
				}

				m_pChannelMgr->deleteChannel(cNum);
			}
		}

		//Send our disconnect message
		//Allocate our packet
		BinaryPacket *pBP = new BinaryPacket();
		if (pBP && pBP->init(len) )
		{
			//Write the packet data
			pBP->writeByte( SSH_MSG_DISCONNECT);
			pBP->writeUint32(SSH_DISCONNECT_BY_APPLICATION);
			pBP->writeString( (char*)pDesc, (uint32)strlen(pDesc));
			pBP->writeString( (char*)pLang, 0);

			result = m_pChannelMgr->queueOutboundData(pBP);
		}
		else
			result = PTSSH_ERR_CouldNotAllocateMemory;

		//Wait for the thread to exit
		m_pTransport->stopThread();
		PTLOG((LL_debug2, "[PTssh] Transport has shutdown\n"));
	}
	else
	{
		//Send a channel close message to all active channels
		for (uint32 cNum = 0; cNum < PTSSH_MAX_CHANNELS; cNum++)
		{
			if ( m_pChannelMgr && m_pChannelMgr->isValidChannelNumber(cNum))
				m_pChannelMgr->deleteChannel(cNum, false);
		}
	}

	m_bIsConnected = false;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::getServerHostKey( uint8**ppBuf, uint32 &bufLen, bool bAsMD5_hash)
{
	if ( m_pTransport)
		return m_pTransport->getServerHostKey(ppBuf, bufLen, bAsMD5_hash);

	return PTSSH_ERR_NullPointer;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::authByPassword(const char * pPassword, const char * pOldPassword)
{
	int32 result;

	//First check our service type and change if needed
	if ( m_serviceType != PST_UserAuth){
		PTLOG((LL_debug2, "[PTssh] Requesting ssh-userauth service\n"));
		result = setServiceType( PST_UserAuth);
		if ( result != PTSSH_SUCCESS)
		{
			PTLOG((LL_error, "[PTssh] Failed to get ssh-userauth service\n"));
			return result;
		}

		PTLOG((LL_debug2, "[PTssh] Successfully changed to ssh-userauth service type\n"));
	}

	uint32 
		usernameLen = (uint32) strlen(this->m_pUsername),
		serviceLen = (uint32) strlen("ssh-connection"),
		passwordLen = (uint32) strlen("password"),
		pPasswordLen = (uint32) strlen( pPassword),
		pOldPwdLen = pOldPassword ? (uint32) strlen(pOldPassword) : 0,
		len =
		1 +                //byte      SSH_MSG_USERAUTH_REQUEST
		4 + usernameLen +  //string    user name
		4 + serviceLen +   //string    service name
		4 + passwordLen +  //string    "password"
		1 +                //boolean   FALSE
		4 + pPasswordLen;  //string    plaintext password in ISO-10646 UTF-8 encoding [RFC3629]

	if ( pOldPassword)	//If true, this is actually a change password request AND authentication
		len += 4 + pOldPwdLen;

	//Create our packet
	BinaryPacket *pBP = new BinaryPacket();
	if (pBP && pBP->init(len) )
	{
		pBP->writeByte(SSH_MSG_USERAUTH_REQUEST);
		pBP->writeString(m_pUsername, usernameLen);
		pBP->writeString("ssh-connection", serviceLen);
		pBP->writeString("password", passwordLen);
		pBP->writeBoolean( pOldPassword? true : false);
		if ( pOldPassword)
			pBP->writeString(pOldPassword, pOldPwdLen);
		pBP->writeString(pPassword, pPasswordLen);

		PTLOG((LL_debug2, "Sending an authentication by password request\n"));
		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result == PTSSH_SUCCESS)
		{
			//TODO: Fix the "result=", they need properly defined
			//Now let's wait until we get an auth response
			switch( m_pTransport->getAuthResult()){
				case SSH_MSG_USERAUTH_SUCCESS:
					PTLOG((LL_info, "User authenticated!\n"));
					m_bAuthenticated = true;
					m_serviceType = PST_Connection;
					result = PTSSH_SUCCESS;
					break;
				case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
					PTLOG((LL_info, "Authentication requires a password change\n"));
					result = PTSSH_ServerRequiresChangePassword;
					break;
				case SSH_MSG_USERAUTH_FAILURE:
					PTLOG((LL_info, "User FAILED to authenticate\n"));
					//TODO: Add in ability to get any message from the server about the failure
					result = PTSSH_ERR_ErrorCouldNotAuthenticate;
					break;
				case SSH_MSG_USERAUTH_BANNER:
					PTLOG((LL_info, "Banner message recieved??\n"));
				default:
					result = -1;
			}
		}
		else
		{
			delete pBP;
			result = PTSSH_ERR_CouldNotQueuePacketForSending;
		}
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
/***************** WORK IN PROGRESS******************/
/* For convenience, this takes a public key blob that is in base64 encoding,
 * and a private key blob that is also base64 encoded. */
int32
PTssh::authByPublicKey(
	const uint8 *pPublicKeyBlob64, uint32 pPublicKeyBlob64Len,
	const uint8 *pPrivateKeyBlob64, uint32 pPrivateKeyBlob64Len, 
	const char *passphrase)
{
	int32
		result;
	PTsshPublicKeyType 
		publicKeyType = PKT_Unknown;
	const char
		publickey[] = "publickey",
		serviceName[] = "ssh-connection",
		SSH_RSA[] = "ssh-rsa",
		SSH_DSS[] = "ssh-dss";
	uint32
		usernameLen = (uint32)strlen(m_pUsername),
		serviceNameLen = (uint32)strlen(serviceName),
		publicKeyStrLen = (uint32)strlen(publickey),
		publicKeyAlgStrLen,
		pPublicKeyBlobLen = 0,
		pPrivateKeyBlobLen = 0,
		sigLen = 0,
		sigDataLen = 0,
		len = 0,
		algorithmStrLen = 0;

	uint8
		*pPublicKeyBlob = NULL,
		*pPrivateKeyBlob = NULL,
		*pSig = NULL,
		*pSigData = NULL,
		*pIter = NULL;
	BinaryPacket 
		*pBP = NULL;


	//Check parameters
	if (pPublicKeyBlob64 == NULL || pPublicKeyBlob64Len == 0)
		return PTSSH_ERR_ZeroLengthPublicKey;

	if (pPrivateKeyBlob64 == NULL || pPrivateKeyBlob64Len == 0)
		return PTSSH_ERR_ZeroLengthPrivateKey;

	//Decode the keys from base64
	result = decodeBase64( pPublicKeyBlob64, pPublicKeyBlob64Len, &pPublicKeyBlob, pPublicKeyBlobLen);
	if ( result != PTSSH_SUCCESS)
		goto publicKeyAuthError;

	result = decodeBase64( pPrivateKeyBlob64, pPrivateKeyBlob64Len, &pPrivateKeyBlob, pPrivateKeyBlobLen);
	if ( result != PTSSH_SUCCESS)
		goto publicKeyAuthError;

	algorithmStrLen = PTSSH_htons32( (uint32*)pPublicKeyBlob );

	//Let's see if the public key is valid and is a type we support
	if ( algorithmStrLen == strlen(SSH_RSA) || algorithmStrLen == strlen(SSH_DSS))
	{
		if (memcmp(pPublicKeyBlob + 4, SSH_RSA, strlen(SSH_RSA))  == 0)
		{
			publicKeyType = PKT_RSA;
			publicKeyAlgStrLen = (uint32) strlen(SSH_RSA);
		}
		else if (memcmp(pPublicKeyBlob + 4, SSH_DSS, strlen(SSH_DSS))  == 0)
		{
			publicKeyType = PKT_DSS;
			publicKeyAlgStrLen = (uint32) strlen (SSH_DSS);
		}
	}

	if ( publicKeyType != PKT_RSA && publicKeyType != PKT_DSS)
	{
		result = PTSSH_ERR_InvalidPublicKeyType;
		goto publicKeyAuthError;
	}

	//byte      SSH_MSG_USERAUTH_REQUEST
	//string    user name
	//string    service name
	//string    "publickey"
	//boolean   TRUE
	//string    public key algorithm name
	//string    public key to be used for authentication
	//string    signature{
	//	// The value of 'signature' is a signature by the corresponding private
	//	// key over the following data, in the following order:
	//	string    session identifier
	//	byte      SSH_MSG_USERAUTH_REQUEST
	//	string    user name
	//	string    service name
	//	string    "publickey"
	//	boolean   TRUE
	//	string    public key algorithm name
	//	string    public key to be used for authentication

	sigLen = 0,
	sigDataLen =
		1 +                       //byte      SSH_MSG_USERAUTH_REQUEST
		4 + usernameLen +         //string    user name in ISO-10646 UTF-8 encoding [RFC3629]
		4 + serviceNameLen +      //string    service name in US-ASCII
		4 + publicKeyStrLen +     //string    "publickey"
		1 +                       //boolean   TRUE
		4 + publicKeyAlgStrLen +  //string    public key algorithm name (ssh-rsa, ssh-dss)
		4 + pPublicKeyBlobLen;    //string    decoded public key blob
	
	pSigData = new uint8[sigDataLen];
	if ( ! pSigData)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto publicKeyAuthError;
	}

	//Fill in the details of the data that we will use to sign
	pIter = pSigData;

	//byte      SSH_MSG_USERAUTH_REQUEST
	*pIter = SSH_MSG_USERAUTH_REQUEST;	
	pIter += 1;

	//string    user name in ISO-10646 UTF-8 encoding [RFC3629]
	PTSSH_htons32(usernameLen, (uint32*)pIter);
	pIter += 4;
	memcpy( pIter, m_pUsername, usernameLen);
	pIter += usernameLen;

	//string    service name in US-ASCII
	PTSSH_htons32(serviceNameLen, (uint32*)pIter);
	pIter += 4;
	memcpy( pIter, serviceName, serviceNameLen);
	pIter += serviceNameLen;

	//string    "publickey"
	PTSSH_htons32(publicKeyStrLen, (uint32*)pIter);
	pIter += 4;
	memcpy( pIter, publickey, publicKeyStrLen);
	pIter += publicKeyStrLen;

	//boolean   TRUE
	*pIter = 1;	
	pIter += 1;

	//string    public key algorithm name
	PTSSH_htons32(publicKeyAlgStrLen, (uint32*)pIter);
	pIter += 4;
	if (publicKeyType == PKT_RSA)
		memcpy( pIter, SSH_RSA, publicKeyAlgStrLen);
	else
		memcpy( pIter, SSH_DSS, publicKeyAlgStrLen);
	pIter += publicKeyAlgStrLen;

	//string    public key blob
	PTSSH_htons32( pPublicKeyBlobLen, (uint32*)pIter);
	pIter += 4;
	memcpy( pIter, pPublicKeyBlob, pPublicKeyBlobLen);
	pIter += pPublicKeyBlobLen;

	/* Check our service type and change if needed.
	 * Note: This must be BEFORE the createSignature call. Otherwise a race condition
	 * will exist and the sessionID will likely not have been set yet
	 */
	if ( m_serviceType != PST_UserAuth){
		PTLOG((LL_debug2, "[PTssh] Requesting ssh-userauth service\n"));
		result = setServiceType( PST_UserAuth);
		if ( result != PTSSH_SUCCESS)
		{
			PTLOG((LL_error, "[PTssh] Failed to get ssh-userauth service\n"));
			goto publicKeyAuthError;
		}

		PTLOG((LL_debug2, "[PTssh] Successfully changed to ssh-userauth service type\n"));
	}

	//Ask the transport object ( PTsshSocket -> CryptoStuff ) to create a signature for us
	result = m_pTransport->createSignature(
		pSigData,  //Data to perform the signature over
		sigDataLen,//Length of data
		pPublicKeyBlob,
		pPublicKeyBlobLen,
		pPrivateKeyBlob,
		pPrivateKeyBlobLen,
		&pSig,     //pointer that will point to the created signature
		sigLen);   //length of the signature
	if ( result != PTSSH_SUCCESS)
		goto publicKeyAuthError;

	len =
		1 +                       //byte      SSH_MSG_USERAUTH_REQUEST
		4 + usernameLen +         //string    user name in ISO-10646 UTF-8 encoding [RFC3629]
		4 + serviceNameLen +      //string    service name in US-ASCII
		4 + publicKeyStrLen +     //string    "publickey"
		1 +                       //boolean   TRUE
		4 + publicKeyAlgStrLen +  //string    public key algorithm name (ssh-rsa, ssh-dss)
		4 + pPublicKeyBlobLen +   //string    decoded public key blob
		/* The signature is a little weird, we have to stick on the SSH string of the
		  * algorithm that did the signature on the front of it */
		4 + 				      //string    signature: compund ssh object...
		4 + publicKeyAlgStrLen +
		4 + sigLen;


	//Create our packet
	pBP = new BinaryPacket();
	if (pBP && pBP->init(len) )
	{
		pBP->writeByte(SSH_MSG_USERAUTH_REQUEST);
		pBP->writeString(m_pUsername, usernameLen);
		pBP->writeString(serviceName, serviceNameLen);
		pBP->writeString(publickey, publicKeyStrLen);
		pBP->writeBoolean(true);
		if (publicKeyType == PKT_RSA)
			pBP->writeString(SSH_RSA, (uint32) strlen(SSH_RSA));
		else
			pBP->writeString(SSH_DSS, (uint32) strlen(SSH_DSS));
		pBP->writeString( (char*)pPublicKeyBlob, pPublicKeyBlobLen);

		//we write the signature string in a few pieces...
		pBP->writeUint32( 4 + publicKeyAlgStrLen + 4 + sigLen);
		if (publicKeyType == PKT_RSA)
			pBP->writeString(SSH_RSA, (uint32) strlen(SSH_RSA));
		else
			pBP->writeString(SSH_DSS, (uint32) strlen(SSH_DSS));
		pBP->writeString( (char*)pSig, sigLen);

		delete pSig;
		pSig = 0;
		sigLen = 0;

		PTLOG((LL_debug1, "[PTssh] Sending an authentication by public key request\n"));
		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result != PTSSH_SUCCESS)
			delete pBP;
		else
		{
			//Now let's wait until we get an auth response
			switch( m_pTransport->getAuthResult()){
				case SSH_MSG_USERAUTH_SUCCESS:
					PTLOG((LL_info, "[PTssh] User authenticated by public/private key pair!\n"));
					m_bAuthenticated = true;
					result = PTSSH_SUCCESS;
					break;
				case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
					PTLOG((LL_info, "Authentication requires a password change\n"));
					result = 2;
					break;
				case SSH_MSG_USERAUTH_FAILURE:
					PTLOG((LL_error, "User FAILED to authenticate\n"));
					result = 0;
					break;
				case SSH_MSG_USERAUTH_BANNER:
					PTLOG((LL_info, "Banner message recieved??\n"));
				default:
					result = -1;
			}
		}
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

publicKeyAuthError:

	if ( pPublicKeyBlob)
		delete pPublicKeyBlob;
	
	if ( pPrivateKeyBlob)
		delete pPrivateKeyBlob;

	if ( pSigData)
		delete pSigData;

	return result;
}

/////////////////////////////////////////////////////////////////////////////////
int32
PTssh::isAuthSupported(PTsshAuthMethod authType, bool &bResult)
{
	int32
		result = PTSSH_SUCCESS;
	const char
		pNone[] = "none",
		pHostbased[] = "hostbased",
		pPassword[] = "password",
		pPublickey[] = "publickey",
		pKeybdInt[] = "keyboard-interactive";
	char 
		*pAuthType = NULL;

	bResult = false;

	//Validate the authentication method type
	switch(authType){
		case PTsshAuth_None:
			pAuthType = (char*)pNone;
			break;
		case PTsshAuth_HostBased:
			pAuthType = (char*)pHostbased;
			break;
		case PTsshAuth_PublicKey:
			pAuthType = (char*)pPublickey;
			break;
		case PTsshAuth_Password:
			pAuthType = (char*)pPassword;
			break;
		case PTsshAuth_KeyboardInteractive:
			pAuthType = (char*)pNone;
			break;
		default:
			return PTSSH_ERR_InvalidAuthenticationMethod;
	}

	//Did we already get the authentication methods from the server?
	if ( ! m_pAuthMethods )
	{
		result = getAuthMethods();
		if ( result != PTSSH_SUCCESS)
			return result;
	}

	//Quick sanity check
	if ( m_pAuthMethods)
	{
		//PTLOG(("Supported authentication methods: %s\n", m_pAuthMethods));
		if ( strstr(m_pAuthMethods, pAuthType))
			bResult = true;
	}

	return result;
}

/////////////////////////////////////////////////////////////////////////////////
int32
PTssh::isPublicKeyAcceptable(
	bool &bResult,
	const char *pPublicKeyBlob64, 
	uint32 pPublicKeyBlob64Len,
	const char *pPrivateKeyBlob64,
	uint32 pPrivateKeyBlob64Len,
	const char *passphrase)
{
	return PTSSH_NOT_IMPLEMENTED;
/*
	int32
		result = PTSSH_SUCCESS;
	const char
		publickey[] = "publickey",
		serviceName[] = "ssh-connection",
		SSH_RSA[] = "ssh-rsa",
		SSH_DSS[] = "ssh-dss";
	bResult = false;

	if ( strcmp(pBublicKeyName, SSH_RSA) == 0)
		type = PKT_RSA;
	else if (strcmp(pBublicKeyName, SSH_DSS) == 0)
		type = PKT_DSS;
	else
		return PTSSH_ERR_InvalidPublicKeyType;

	//First check our service type and change if needed
	if ( m_serviceType != PST_UserAuth){
		PTLOG(("[PTssh] Requesting ssh-userauth service\n"));
		result = setServiceType( PST_UserAuth);
		if ( result != PTSSH_SUCCESS)
		{
			PTLOG(("[PTssh] Failed to get ssh-userauth service\n"));
			return result;
		}

		PTLOG(("[PTssh] Successfully changed to ssh-userauth service type\n"));
	}

	uint32 
		len =
			1 +                       //byte      SSH_MSG_USERAUTH_REQUEST
			4 + strlen(m_pUsername) + //string    user name in ISO-10646 UTF-8 encoding [RFC3629]
			4 + strlen(serviceName) + //string    service name in US-ASCII
			4 + strlen(publickey) +   //string    "publickey"
			1 +                       //boolean   FALSE
			4 +                       //string    public key algorithm name
			type == PKT_RSA ? strlen(SSH_RSA) : strlen (SSH_DSS) +
			4 + blobLen;              //string    public key blob

	//Create our packet
	BinaryPacket *pBP = new BinaryPacket();
	if (pBP && pBP->init(len) )
	{
		pBP->writeByte(SSH_MSG_USERAUTH_REQUEST);
		pBP->writeString(m_pUsername, strlen(m_pUsername));
		pBP->writeString(serviceName, strlen(serviceName));
		pBP->writeString(publickey, strlen(publickey));
		pBP->writeBoolean(false);
		if (type == PKT_RSA)
			pBP->writeString(SSH_RSA, strlen(SSH_RSA));
		else
			pBP->writeString(SSH_DSS, strlen(SSH_DSS));
		pBP->writeString(pKeyBlob, blobLen);
				
		PTLOG(("[PTssh] Checking if the given public key is acceptable\n"));
		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result != PTSSH_SUCCESS)
			delete pBP;
		else
		{
			//Now let's wait until we get an auth response
			result = m_pTransport->getPublicKeyAcceptableResult(bResult);
		}
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
*/
}

/////////////////////////////////////////////////////////////////////////////////
int32
PTssh::getAuthMethods()
{
	int32 
		result = PTSSH_SUCCESS;

	//First check our service type and change if needed
	if ( m_serviceType != PST_UserAuth){
		PTLOG((LL_debug2, "[PTssh] Requesting ssh-userauth service\n"));
		result = setServiceType( PST_UserAuth);
		if ( result != PTSSH_SUCCESS)
		{
			PTLOG((LL_error, "[PTssh] Failed to get ssh-userauth service\n"));
			return result;
		}

		PTLOG((LL_debug2, "[PTssh] Successfully changed to ssh-userauth service type\n"));
	}

	uint32
		usernameLen = (uint32) strlen(this->m_pUsername),
		serviceLen = (uint32) strlen("ssh-connection"),
		noneLen = (uint32) strlen("none"),
		len =
			1 +                //byte      SSH_MSG_USERAUTH_REQUEST
			4 + usernameLen +  //string    user name
			4 + serviceLen +   //string    service name
			4 + noneLen;       //string    "password"

	//Create our packet
	BinaryPacket *pBP = new BinaryPacket();
	if (pBP && pBP->init(len) )
	{
		pBP->writeByte(SSH_MSG_USERAUTH_REQUEST);
		pBP->writeString(m_pUsername, usernameLen);
		pBP->writeString("ssh-connection", serviceLen);
		pBP->writeString("none", noneLen);

		PTLOG((LL_debug2, "Sending \"none\" authentication request to get available auth methods\n"));
		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result == PTSSH_SUCCESS)
		{
			//TODO: Fix the "result=", they need properly defined
			//Now let's wait until we get an auth response
			switch( m_pTransport->getAuthResult()){
				case SSH_MSG_USERAUTH_SUCCESS:
					PTLOG((LL_info, "User authenticated... wtf?!\n"));
					break;
				case SSH_MSG_USERAUTH_FAILURE:
					if ( m_pAuthMethods)
						delete m_pAuthMethods;

					m_pAuthMethods = m_pTransport->getAllowedAuthTypes();
					break;
				default:
					result = -1;
			}
		}
		else
		{
			delete pBP;
			result = PTSSH_ERR_CouldNotQueuePacketForSending;
		}
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::createChannel_session(uint32 &channelNumber)
{
	int32 result = PTSSH_SUCCESS;
	uint32 
		channelTypeStrLen = (uint32) strlen("session"),
		len =
		1 +						//byte	SSH_MSG_CHANNEL_OPEN
		4 + channelTypeStrLen +	//string    channel type in US-ASCII only
		4 +						//uint32    sender channel
		4 +						//uint32    initial window size
		4;						//uint32    maximum packet size
	
	//Create our packet
	BinaryPacket *pBP = new BinaryPacket();
	if (pBP && pBP->init(len) )
	{
		uint32 
			cNum;
		
		result = m_pChannelMgr->newChannel(PTSSH_DEFAULT_WINDOW_SIZE, PTSSH_MAX_PACKET_SIZE, PTsshCT_session, cNum);
		if ( result != PTSSH_SUCCESS)
		{
			delete pBP;
			return result;
		}

		pBP->writeByte( SSH_MSG_CHANNEL_OPEN);
		pBP->writeString("session", channelTypeStrLen);
		pBP->writeUint32( (uint32) cNum );
		pBP->writeUint32( PTSSH_DEFAULT_WINDOW_SIZE);
		pBP->writeUint32( PTSSH_MAX_PACKET_SIZE);

		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result == PTSSH_SUCCESS)
		{
			result = m_pChannelMgr->getChannelCreateResult( cNum);
			if ( result != PTSSH_SUCCESS)
			{
				m_pChannelMgr->deleteChannel( cNum, false);
				return result;
			}

			//Set the new channel number
			channelNumber = cNum;
		}
		else
		{
			delete pBP;
			result = PTSSH_ERR_CouldNotQueuePacketForSending;
		}
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::requestRemotePortFowarding(
	void (*pCallbackFunc)(struct PTsshCallBackData*),
	void *pCallbackData,
	const char *IPAddr,
	uint16 port,
	uint32 maxConnections)
{
	int32 
		result = PTSSH_SUCCESS;

	const char *
		pTcpForward = "tcpip-forward";

	uint32 
		channelTypeStrLen = (uint32) strlen("session"),
		len =
			1 +                               // byte      SSH_MSG_GLOBAL_REQUEST
			4 + (uint32)strlen(pTcpForward) + // string    "tcpip-forward"
			1 +                               // boolean   want reply
			4 + (uint32)strlen(IPAddr) +      // string    address to bind (e.g., "0.0.0.0")
			4;                                // uint32    port number to bind
	
	if ( ! pCallbackFunc)
		return PTSSH_ERR_CallbackFunctionPointerCanNotBeNull;

	struct PTsshCallBackData *pCBD = new PTsshCallBackData( this);
	if ( ! pCBD)
		return PTSSH_ERR_CouldNotAllocateMemory;

	pCBD->pCallBackFunc = pCallbackFunc;
	pCBD->pDeveloperData = pCallbackData;

	//Create our packet
	BinaryPacket *pBP = new BinaryPacket();
	if (pBP && pBP->init(len) )
	{
		uint32 
			cNum;
		
		result = m_pChannelMgr->newChannel(PTSSH_DEFAULT_WINDOW_SIZE, PTSSH_MAX_PACKET_SIZE, PTsshCT_forwarded_tcpip, cNum);
		if ( result == PTSSH_SUCCESS)
		{
			//Set some needed data for later
			m_pChannelMgr->setForwardNotifierCallbackData( cNum, pCBD);
			pCBD = NULL;  //The Channel class now ownes this pointer
			result = m_pChannelMgr->setForwardedTcpIpData( cNum, IPAddr, port);
			if ( result == PTSSH_SUCCESS)
			{	
				pBP->writeByte(SSH_MSG_GLOBAL_REQUEST);
				pBP->writeString(pTcpForward, (uint32)strlen(pTcpForward));
				pBP->writeBoolean( true);
				pBP->writeString( IPAddr, (uint32)strlen(IPAddr));
				pBP->writeUint32( port);

				result = m_pChannelMgr->queueOutboundData( pBP);
				if ( result == PTSSH_SUCCESS)
				{
					pBP = NULL;
					result = m_pTransport->getGlobalRequestResult();
				}
			}
			else
				m_pChannelMgr->deleteChannel(cNum, false);
		}
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	if ( pBP)
		delete pBP;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::cancelRemotePortFowarding(const char *IPAddr, uint16 port)
{
	int32 
		result = PTSSH_SUCCESS;

	const char *
		pTcpCancel = "cancel-tcpip-forward";

	uint32 
		channelTypeStrLen = (uint32) strlen("session"),
		len =
			1 +                         // byte      SSH_MSG_GLOBAL_REQUEST
			4 + (uint32)strlen(pTcpCancel) +   // string    "cancel-tcpip-forward"
			1 +                         // boolean   want reply
			4 + (uint32)strlen(IPAddr) +        // string    address to bind (e.g., "0.0.0.0")
			4;                          // uint32    port number to bind
	
	//Create our packet
	BinaryPacket *pBP = new BinaryPacket();
	if (pBP && pBP->init(len) )
	{
		pBP->writeByte(SSH_MSG_GLOBAL_REQUEST);
		pBP->writeString(pTcpCancel, (uint32)strlen(pTcpCancel));
		pBP->writeBoolean( true);
		pBP->writeString( IPAddr, (uint32)strlen(IPAddr));
		pBP->writeUint32( port);

		result = m_pChannelMgr->queueOutboundData( pBP);
		if ( result == PTSSH_SUCCESS)
		{
			pBP = NULL;
			result = m_pTransport->getGlobalRequestResult();
		}
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	if ( pBP)
		delete pBP;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::createChannel_directTCPIP(
    uint32 &cNum,
	const char *destAddr,
	uint16 destPort,
	const char *sourceIPAddr,
	uint16 sourcePort)
{
	int32 
		result = PTSSH_SUCCESS;
	int
		sock = PTSSH_BAD_SOCKET_NUMBER;
	const char
		*pChannelType = "direct-tcpip";

	uint32 
		len =
			1 +	                              //byte      SSH_MSG_CHANNEL_OPEN
			4 + (uint32)strlen(pChannelType) +//string    "direct-tcpip"
			4 +                               //uint32    sender channel
			4 +                               //uint32    initial window size
			4 +                               //uint32    maximum packet size
			4 + (uint32)strlen(destAddr) +    //string    host to connect
			4 +                               //uint32    port to connect
			4 + (uint32)strlen(sourceIPAddr) +//string    originator IP address
			4;                                //uint32    originator port

	//Create our packet
	BinaryPacket *pBP = new BinaryPacket();
	if (pBP && pBP->init(len) )
	{
		result = m_pChannelMgr->newChannel( PTSSH_DEFAULT_WINDOW_SIZE, PTSSH_MAX_RAW_BUF_IN_SIZE, PTsshCT_direct_tcpip, cNum);
		if ( result != PTSSH_SUCCESS)
		{
			delete pBP;
			return result;
		}

		pBP->writeByte(   SSH_MSG_CHANNEL_OPEN);
		pBP->writeString( pChannelType, (uint32) strlen(pChannelType));
		pBP->writeUint32( cNum );
		pBP->writeUint32( PTSSH_DEFAULT_WINDOW_SIZE);
		pBP->writeUint32( PTSSH_MAX_RAW_BUF_IN_SIZE);
		pBP->writeString( destAddr, (uint32) strlen(destAddr));
		pBP->writeUint32( destPort);
		pBP->writeString( sourceIPAddr, (uint32) strlen(sourceIPAddr));
		pBP->writeUint32( sourcePort);

		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result == PTSSH_SUCCESS)
		{
			result = m_pChannelMgr->getChannelCreateResult( cNum);
			if ( result != PTSSH_SUCCESS)
			{
				m_pChannelMgr->deleteChannel( cNum, false);
				return result;
			}
		}
		else
		{
			delete pBP;
			result = PTSSH_ERR_CouldNotQueuePacketForSending;
		}
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32 
PTssh::createChannel_AutomaticDirectTCPIP(
	int localSocket,
	int totalConnections,
	int32 (*callbackFuncPtr)(void *ptrStorage),
	const char *destAddress,
	uint16 destPort,
	const char *sourceIPAddress,
	uint16 sourcePort)
{
	int32
		result;

	//Create a new tunnelHandler and let it do the work 
	TcpIpTunnelHandler *pTH = new TcpIpTunnelHandler (this, m_pChannelMgr);

	//Give it it's mission details and let it get to work!
	result = pTH->init(
		localSocket,
		totalConnections,
		callbackFuncPtr,
		destAddress,
		destPort,
		sourceIPAddress,
		sourcePort);
	if ( result == PTSSH_SUCCESS)
	{
		pthread_mutex_lock( &m_TcpIpTunnelHandlerMutex);
			m_pTcpIpHandlers->insertAtEnd( pTH);
		pthread_mutex_unlock( &m_TcpIpTunnelHandlerMutex);
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::closeAutomaticDirectTCPIP( int localSocket)
{
	int32 result = PTSSH_ERR_NoMatchingAutomaticDirectTCPIPFound;
	if (m_pTcpIpHandlers)
	{
		bool bFound = false;
		TunnelHandler *pTH = NULL;

		pthread_mutex_lock( &m_TcpIpTunnelHandlerMutex);
		for (uint32 ctr = 0; ctr < m_pTcpIpHandlers->size(); ctr++)
		{
			pTH = (TunnelHandler*) m_pTcpIpHandlers->peek(ctr);
			if ( pTH)
			{
				if (pTH->getListenSocketNumber() == localSocket)
				{
					m_pTcpIpHandlers->remove(ctr);  //Don't worry about return value, already got it
					bFound = true;
					break;
				}
			}
		}
		pthread_mutex_unlock( &m_TcpIpTunnelHandlerMutex);

		if (bFound && pTH)
		{
			pTH->shutdown();
			delete pTH;
		}
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::closeChannel(uint32 localChannelNumber)
{
	uint32 
		len =
			1 +		//byte SSH_MSG_CHANNEL_CLOSE
			4;		//uint32 recipient channel
	int32
		result = PTSSH_SUCCESS;
	uint32
		remoteChannelNum;
	bool
		bChannelOpen = false,
		bCloseMsgSent = false;
	
	//Validate channel number
	if ( ! m_pChannelMgr->isValidChannelNumber(localChannelNumber))
		return PTSSH_ERR_InvalidChannelNumber;

	if ( m_pChannelMgr->isOpen(localChannelNumber, bChannelOpen) == PTSSH_SUCCESS && bChannelOpen)
	{
		//Check to see if we have already sent a Close message to the channel, and if not, close it
		if (m_pChannelMgr->bAlreadySentCloseMsg(localChannelNumber, bCloseMsgSent) == PTSSH_SUCCESS && (! bCloseMsgSent))
		{
			m_pChannelMgr->getRemoteChannelNumber(localChannelNumber, remoteChannelNum );

			PTLOG((LL_debug2, "[PTssh] Closing local cNum %d, remote cNum %d\n",
				localChannelNumber, remoteChannelNum));

			//Create our packet
			BinaryPacket *pBP = new BinaryPacket(localChannelNumber);
			if (pBP && pBP->init(len) )
			{
				pBP->writeByte( SSH_MSG_CHANNEL_CLOSE);
				pBP->writeUint32( remoteChannelNum);
				
				result = m_pChannelMgr->queueOutboundData(pBP);
				if ( result != PTSSH_SUCCESS)
					delete pBP;

				//Wait for the channel to close
				m_pChannelMgr->waitForChannelClose(localChannelNumber);

				//Free the channel's resources
				m_pChannelMgr->deleteChannel(localChannelNumber);
			}
			else
				return PTSSH_ERR_CouldNotAllocateMemory;
		}
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::channelRequest_pty(
		uint32 localChannelNumber,
		const char * pTerminalType,
		uint32 termCharWidth,
		uint32 termCharHeight,
		uint32 termPixWidth,
		uint32 termPixHeight,
		const char * pTermModes)
{
	const char 
		*pRequest = "pty-req";
	int32
		result;
	uint32 
		len =
			1 +							//byte	SSH_MSG_CHANNEL_REQUEST
			4 +							//uint32    recipient channel
			4 + (uint32) strlen(	pRequest) +		//string    "pty-req"
			1 +							//boolean   want_reply
			4 +(uint32)  strlen(	pTerminalType)+	//string    TERM environment variable value (e.g., vt100)
			4 +							//uint32    terminal width, characters (e.g., 80)
			4 +							//uint32    terminal height, rows (e.g., 24)
			4 +							//uint32    terminal width, pixels (e.g., 640)
			4 +							//uint32    terminal height, pixels (e.g., 480)
			4 + (uint32) strlen( pTermModes),//string    encoded terminal modes
		remoteChannelNum;
	
	//Validate channel number
	if ( ! m_pChannelMgr->isValidChannelNumber(localChannelNumber))
		return PTSSH_ERR_InvalidChannelNumber;

	m_pChannelMgr->getRemoteChannelNumber(localChannelNumber, remoteChannelNum );

	//Allocate our packet
	BinaryPacket *pBP = new BinaryPacket(localChannelNumber);
	if (pBP && pBP->init(len) )
	{
		//Write the packet data
		pBP->writeByte( SSH_MSG_CHANNEL_REQUEST);
		pBP->writeUint32(remoteChannelNum);
		pBP->writeString( pRequest, (uint32) strlen( pRequest));
		pBP->writeBoolean( true);
		pBP->writeString( (char*)pTerminalType, (uint32) strlen(pTerminalType));
		pBP->writeUint32( termCharWidth);
		pBP->writeUint32( termCharHeight);
		pBP->writeUint32( termPixWidth);
		pBP->writeUint32( termPixHeight);
		pBP->writeString( (char*)pTermModes,(uint32)  strlen(pTermModes));

		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result == PTSSH_SUCCESS)
			result = m_pChannelMgr->getChannelRequestResult( localChannelNumber);
		else
			delete pBP;
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::channelRequest_shell(	uint32 localChannelNumber)
{
	const char
		*pShell = "shell";
	int32
		result;
	uint32 
		len =
			1 +					//byte      SSH_MSG_CHANNEL_REQUEST
			4 +					//uint32    recipient channel
			4 + (uint32) strlen(pShell) +//string    "shell"
			1,					//boolean   want reply
		remoteChannelNum;
	
	//Validate channel number
	if ( ! m_pChannelMgr->isValidChannelNumber(localChannelNumber))
		return PTSSH_ERR_InvalidChannelNumber;

	m_pChannelMgr->getRemoteChannelNumber(localChannelNumber, remoteChannelNum );

	//Allocate our packet
	BinaryPacket *pBP = new BinaryPacket(localChannelNumber);
	if (pBP && pBP->init(len) )
	{
		//Write the packet data
		pBP->writeByte( SSH_MSG_CHANNEL_REQUEST);
		pBP->writeUint32(remoteChannelNum);
		pBP->writeString( pShell, (uint32) strlen( pShell));
		pBP->writeBoolean( true);

		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result == PTSSH_SUCCESS)
		{
			result = m_pChannelMgr->getChannelRequestResult( localChannelNumber);
		}
		else
			delete pBP;
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::channelRequest_x11Forwarding(
		uint32 localChannelNumber,
		uint32 screenNumber,
		bool bSingleConnectionOnly)
{
	int32 result;
	const char
		*pX11Req = "x11-req",
		*pAuthProtocol ="MIT-MAGIC-COOKIE-1";
	char
		pAuthCookie[PTSSH_X11_AUTH_COOKIE_LEN + 1]; //Cause sprintf writes data + NULL

	uint32
		remoteChannelNum = PTSSH_BAD_CHANNEL_NUMBER,
		len =  
			1 +                        //byte      SSH_MSG_CHANNEL_REQUEST
      		4 +                        //uint32    recipient channel
			4 + (uint32)strlen(pX11Req) +      //string    "x11-req"
			1 +                        //boolean   want reply
			1 +                        //boolean   single connection
			4 + (uint32)strlen(pAuthProtocol) +//string    x11 authentication protocol
			4 + PTSSH_X11_AUTH_COOKIE_LEN +  //string    x11 authentication cookie
			4;                         //uint32    x11 screen number

	//Validate channel number
	if ( ! m_pChannelMgr->isValidChannelNumber(localChannelNumber))
		return PTSSH_ERR_InvalidChannelNumber;

	m_pChannelMgr->getRemoteChannelNumber(localChannelNumber, remoteChannelNum );

	//Throw together some random crap for an auth cookie
	for (int i = 0; i < PTSSH_X11_AUTH_COOKIE_LEN; i+= 2)
		sprintf( pAuthCookie + i, "%02X", rand() % 255);

	BinaryPacket *pBP = new BinaryPacket(localChannelNumber);
	if ( pBP && pBP->init(len) )
	{
		pBP->writeByte( SSH_MSG_CHANNEL_REQUEST);
		pBP->writeUint32( remoteChannelNum);
		pBP->writeString( pX11Req, (uint32)strlen( pX11Req));
		pBP->writeBoolean( true);
		pBP->writeBoolean( bSingleConnectionOnly);
		pBP->writeString( pAuthProtocol, (uint32)strlen( pAuthProtocol));
		pBP->writeString( pAuthCookie, PTSSH_X11_AUTH_COOKIE_LEN);
		pBP->writeUint32( screenNumber);

		result = m_pChannelMgr->queueOutboundData( pBP);
		if ( result == PTSSH_SUCCESS)
		{
			result = m_pChannelMgr->getChannelRequestResult(localChannelNumber);
			if ( result == PTSSH_SUCCESS)
			{
				result = m_pChannelMgr->setX11ForwardStatus( localChannelNumber, true);
				if ( result != PTSSH_SUCCESS) {
					PTLOG((LL_warning, "[PTssh] Failed to mark channel as having X11 forwarding\n"));
				}
			}
			else
			{
				PTLOG((LL_error, "[PTssh] X11 request failed\n"));
			}
		}
		else
			delete pBP;
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}

/////////////////////////////////////////////////////////////////////////////////
//int32
//PTssh::setX11ChannelHandler(
//		void (*pCallbackFunc)(struct PTsshCallBackData*),
//		void *pCallbackData)
//{
//	if ( pCallbackFunc)
//	{
//		m_pX11CallbackHandler = pCallbackFunc;
//		if (pCallbackData)
//			m_pX11CallbackData = pCallbackData;
//
//		return PTSSH_SUCCESS;
//	}
//	return PTSSH_ERR_CallbackFunctionPointerWasNull;
//}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::channelRequest_env(uint32 localChannelNumber, const char *pVariableName, const char *pVariableValue)
{
	const char
		*pEnv = "env";
	int32
		result;

	uint32 
		len =
			1 +							//byte      SSH_MSG_CHANNEL_REQUEST
			4 +							//uint32    recipient channel
			4 + (uint32) strlen(pEnv) +	//string    "env"
			1 +							//boolean   want reply
			4 + (uint32) strlen(pVariableName) +	//string    variable name
			4 + (uint32) strlen(pVariableValue),	//string    variable value
		remoteChannelNum;
	
	//Validate channel number
	if ( ! m_pChannelMgr->isValidChannelNumber(localChannelNumber))
		return PTSSH_ERR_InvalidChannelNumber;

	m_pChannelMgr->getRemoteChannelNumber(localChannelNumber, remoteChannelNum );

	//Allocate our packet
	BinaryPacket *pBP = new BinaryPacket(localChannelNumber);
	if (pBP && pBP->init(len) )
	{
		//Write the packet data
		pBP->writeByte( SSH_MSG_CHANNEL_REQUEST);
		pBP->writeUint32(remoteChannelNum);
		pBP->writeString( pEnv, (uint32) strlen( pEnv));
		pBP->writeBoolean( true);
		pBP->writeString( (char*)pVariableName, (uint32) strlen( pVariableName));
		pBP->writeString( (char*)pVariableValue, (uint32) strlen( pVariableValue));

		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result == PTSSH_SUCCESS)
		{
			result = m_pChannelMgr->getChannelRequestResult( localChannelNumber);
		}
		else
			delete pBP;
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::channelRequest_exec(uint32 localChannelNumber, const char * pCommand)
{
	const char
		*pExec = "exec";
	int32
		result;

	uint32 
		len =
			1 +					//byte      SSH_MSG_CHANNEL_REQUEST
			4 +					//uint32    recipient channel
			4 + (uint32) strlen(pExec) +	//string    "exec"
			1 +					//boolean   want reply
			4 +(uint32)  strlen(pCommand),//string    command
		remoteChannelNum;
	
	//Validate channel number
	if ( ! m_pChannelMgr->isValidChannelNumber(localChannelNumber))
		return PTSSH_ERR_InvalidChannelNumber;

	m_pChannelMgr->getRemoteChannelNumber(localChannelNumber, remoteChannelNum );

	//Allocate our packet
	BinaryPacket *pBP = new BinaryPacket(localChannelNumber);
	if (pBP && pBP->init(len) )
	{
		//Write the packet data
		pBP->writeByte( SSH_MSG_CHANNEL_REQUEST);
		pBP->writeUint32(remoteChannelNum);
		pBP->writeString( pExec, (uint32) strlen( pExec));
		pBP->writeBoolean( true);
		pBP->writeString( (char*)pCommand, (uint32) strlen( pCommand));

		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result == PTSSH_SUCCESS)
		{
			result = m_pChannelMgr->getChannelRequestResult( localChannelNumber);
		}
		else
			delete pBP;
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::channelRequest_subsystem(uint32 localChannelNumber, const char *pSubsystemName)
{
	const char
		pSubsystem[] = "subsystem";
	int32
		result;

	uint32 
		remoteChannelNum,
		len =
			1 +                               //byte      SSH_MSG_CHANNEL_REQUEST
			4 +	                              //uint32    recipient channel
			4 + (uint32) strlen(pSubsystem) +  //string    "subsystem"
			1 +                               //boolean   want reply
			4 + (uint32) strlen(pSubsystemName);//string    subsystem name
		
	
	//Validate channel number
	if ( ! m_pChannelMgr->isValidChannelNumber(localChannelNumber))
		return PTSSH_ERR_InvalidChannelNumber;

	m_pChannelMgr->getRemoteChannelNumber(localChannelNumber, remoteChannelNum );

	//Allocate our packet
	BinaryPacket *pBP = new BinaryPacket(localChannelNumber);
	if (pBP && pBP->init(len) )
	{
		//Write the packet data
		pBP->writeByte( SSH_MSG_CHANNEL_REQUEST);
		pBP->writeUint32(remoteChannelNum);
		pBP->writeString( pSubsystem, (uint32) strlen( pSubsystem));
		pBP->writeBoolean( true);
		pBP->writeString( pSubsystemName, (uint32) strlen( pSubsystemName));

		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result == PTSSH_SUCCESS)
		{
			result = m_pChannelMgr->getChannelRequestResult( localChannelNumber);
		}
		else
			delete pBP;
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}


///////////////////////////////////////////////////////////////////////////////
int32
PTssh::channelRequest_windowChange(
		uint32 localChannelNumber,
		uint32 termCharWidth,
		uint32 termCharHeight,
		uint32 termPixWidth,
		uint32 termPixHeight)
{
	const char 
		*pWindowChange = "window-change";
	int32
		result;
	uint32 
		len =
			1 +						//byte      SSH_MSG_CHANNEL_REQUEST
			4 +						//uint32    recipient channel
			4 + (uint32) strlen(pWindowChange) +	//string    "window-change"
			1 +						//boolean   want reply
			4 +						//uint32    terminal width, columns
			4 +						//uint32    terminal height, rows
			4 +						//uint32    terminal width, pixels
			4,						//uint32    terminal height, pixels
		remoteChannelNum;
	
	//Validate channel number
	if ( ! m_pChannelMgr->isValidChannelNumber(localChannelNumber))
		return PTSSH_ERR_InvalidChannelNumber;

	m_pChannelMgr->getRemoteChannelNumber(localChannelNumber, remoteChannelNum );

	//Allocate our packet
	BinaryPacket *pBP = new BinaryPacket(localChannelNumber);
	if (pBP && pBP->init(len) )
	{
		//Write the packet data
		pBP->writeByte( SSH_MSG_CHANNEL_REQUEST);
		pBP->writeUint32(remoteChannelNum);
		pBP->writeString( pWindowChange, (uint32) strlen( pWindowChange));
		pBP->writeBoolean( false);
		pBP->writeUint32(termCharWidth);
		pBP->writeUint32(termCharHeight);
		pBP->writeUint32(termPixWidth);
		pBP->writeUint32(termPixHeight);

		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result == PTSSH_SUCCESS)
		{
			result = m_pChannelMgr->getChannelRequestResult( localChannelNumber);
		}
		else
			delete pBP;
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32 
PTssh::channelRequest_sendSignal( const uint32 &localChannelNumber, const PTsshChannelSignalType &eSignalType)
{
	const char 
		*pSignal("signal"),
		*pSignalType;
	int32
		result;

	// Set the signal string for to meet the rfc
	switch(eSignalType)
	{
		case Sig_ABRT:	/**< Abort signal */
			pSignalType = "ABRT";
			break;
		case Sig_ALRM:	/**< Alarm signal */
			pSignalType = "ALRM";
			break;
		case Sig_FPE:
			pSignalType = "FPE";
			break;
		case Sig_HUP:
			pSignalType = "HUP";
			break;
		case Sig_ILL:
			pSignalType = "ILL";
			break;
		case Sig_INT:
			pSignalType = "INT";
			break;
		case Sig_KILL:	/**< Kill signal: used for forcibly killing a process */
			pSignalType = "KILL";
			break;
		case Sig_PIPE:
			pSignalType = "PIPE";
			break;
		case Sig_QUIT:	/**< Quit: used to tell a process to stop */
			pSignalType = "QUIT";
			break;
		case Sig_SEGV:
			pSignalType = "SEGV";
			break;
		case Sig_TERM:
			pSignalType = "TERM";
			break;
		case Sig_USR1:
			pSignalType = "USR1";
			break;
		case Sig_USR2:
			pSignalType = "USR2";
			break;
		default:
				// log unknown
		return PTSSH_ERR_UnknownSignalType;
	}

	uint32 
		len =
			1 +						//byte      SSH_MSG_CHANNEL_REQUEST
			4 +						//uint32    recipient channel
			4 + (uint32) strlen(pSignal) +	//string    "signal"
			1 +						//boolean   want reply
			4 + (uint32) strlen(pSignalType),//string    signal name  
		remoteChannelNum;
	
	//Validate channel number
	if ( ! m_pChannelMgr->isValidChannelNumber(localChannelNumber))
		return PTSSH_ERR_InvalidChannelNumber;

	m_pChannelMgr->getRemoteChannelNumber(localChannelNumber, remoteChannelNum );

	//Allocate our packet
	BinaryPacket *pBP = new BinaryPacket(localChannelNumber);
	if (pBP && pBP->init(len) )
	{
		//Write the packet data
		pBP->writeByte( SSH_MSG_CHANNEL_REQUEST );
		pBP->writeUint32( remoteChannelNum );
		pBP->writeString( pSignal, (uint32) strlen( pSignal) );
		pBP->writeBoolean( true );
		pBP->writeString( pSignalType, (uint32) strlen( pSignalType ));

		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result == PTSSH_SUCCESS)
		{
			result = m_pChannelMgr->getChannelRequestResult( localChannelNumber );
		}
		else
			delete pBP;
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;
	
	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::channelRequest_exitStatus(uint32 channelNumber, uint32 &exitStatus)
{
	return PTSSH_NOT_IMPLEMENTED;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::channelRequest_exitSignal(uint32 channelNumber, uint32 &exitSignal)
{
	return PTSSH_NOT_IMPLEMENTED;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::channelGetEOF(uint32 localChannelNumber, bool &bResult)
{
	uint32
		remoteChannelNum;
	
	//Validate channel number
	if ( ! m_pChannelMgr->isValidChannelNumber(localChannelNumber))
		return PTSSH_ERR_InvalidChannelNumber;

	m_pChannelMgr->getRemoteChannelNumber(localChannelNumber, remoteChannelNum );

	return m_pChannelMgr->getEOF(remoteChannelNum, bResult);
}

#ifdef PTSSH_SFTP
///////////////////////////////////////////////////////////////////////////////
int32
PTssh::initSFTP()
{
	int32
		result = PTSSH_SUCCESS;
	uint32
		SFTPChannelNum = PTSSH_BAD_CHANNEL_NUMBER;

	if ( m_pSftp)   //Already init'd ?
		return result;

	/* First we ask the SSH server for a channel and request the SFTP subsystem
	 * on that channel */
	result = this->createChannel_session(SFTPChannelNum);
	if ( result == PTSSH_SUCCESS)
	{
		PTLOG((LL_debug2, "Requesting sftp subsystem\n"));
		result = channelRequest_subsystem(SFTPChannelNum, "sftp");
		if (result == PTSSH_SUCCESS && SFTPChannelNum != PTSSH_BAD_CHANNEL_NUMBER)
		{
			PTLOG((LL_debug2, "SFTP subsystem accessed!\n"));

			//Now we create our PTSftp object
			m_pSftp = new PTSftp(this, m_pChannelMgr, SFTPChannelNum);
			if ( m_pSftp)
			{
				result = m_pSftp->init();
				if ( result != PTSSH_SUCCESS)
				{
					closeChannel(SFTPChannelNum);
					delete m_pSftp;
					m_pSftp = NULL;
				}
			}
		}
		else
		{
			PTLOG((LL_warning, "No SFTP subsystem available. Error %d\n", result));
			closeChannel(SFTPChannelNum);
		}
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
PTSftp * const 
PTssh::getSftpObj()
{
	if ( m_pSftp)
		return m_pSftp;

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::shutdownSftp()
{
	if ( m_pSftp)
	{

		delete m_pSftp;
		m_pSftp = NULL;
	}

	return PTSSH_SUCCESS;
}
#endif

#ifdef PTSSH_SCP
///////////////////////////////////////////////////////////////////////////////
int32
PTssh::scpSendInit(
	uint32 &cNum,
	uint32 &optimalSize,
	const char *pRemoteFilePath,
	uint64 fileSizeInBytes,
	uint32 fileCreateFlags)
{
	int32 
		result;
	Data 
		*pData = NULL;
	char 
		scpCommand[] = "scp -t ",
		tmp[1024],
		*pTmp = NULL;
	
	//Clear out the buffer
	memset(tmp, 0x0, 1024);

	//Copy in the command 
	memcpy(tmp, scpCommand, strlen(scpCommand));
	//Copy in the filename
	memcpy(tmp + strlen(scpCommand), pRemoteFilePath, strlen(pRemoteFilePath));

	//open a channel
	result = createChannel_session(cNum);
	if ( result != PTSSH_SUCCESS)
		return result;

	//Set the optimal data size
	result = getOptimalDataSize(cNum, optimalSize);
	if ( result != PTSSH_SUCCESS)
		return result;

	//call exec on the channel
	PTLOG((LL_debug2, "[PTssh] Requesting channel %d run command: %s\n", cNum, tmp));
	result = channelRequest_exec(cNum, tmp);
	if ( result != PTSSH_SUCCESS)
		goto error;

	PTLOG((LL_debug3, "[PTssh] Opened channel %d\n", cNum));

	//Get scp ok, channel data should have a boolean 1
	result = channelRead(cNum, &pData, true);
	if ( result != PTSSH_SUCCESS)
		goto error;

	
	if ( pData && ( *(pData->getDataPtr()) != 0) )
	{
		result = PTSSH_ERR_CouldNotStartupSCP;
		goto error;
	}
	PTLOG((LL_debug3, "[PTssh] Read data. Len=%d, data=%u\n", pData->dataLen(), *(pData->getDataPtr())));

	delete pData;
	pData = NULL;

	pTmp = (char*) strrchr(pRemoteFilePath, '/');
	if ( pTmp)
		pTmp++;
	else
		pTmp = (char*)pRemoteFilePath;

	//Clear out the buffer
	memset(tmp, 0x0, 1024);

	//Create the file creation string
	snprintf( tmp, 1024, "C0%o %lu", fileCreateFlags, (long unsigned int)fileSizeInBytes);
	snprintf( tmp + strlen(tmp), 1024 - strlen(tmp), " %s\n", pTmp);

	//Send the file mode, file size and base file name
	PTLOG((LL_debug3, "[PTssh] Writing file creation string on channel %d\n", cNum));
	result = channelWrite(cNum, tmp, (uint32) strlen(tmp));
	if ( result != PTSSH_SUCCESS)
		goto error;

	//Get the ok
	//scp -t /mnt/400gig/msdia80.dll
	PTLOG((LL_debug3, "[PTssh] Reading file creation result on channel %d\n", cNum));
	result = channelRead(cNum, &pData, true);
	if ( result != PTSSH_SUCCESS)
		goto error;

	if ( pData && ( *(pData->getDataPtr()) != 0) )
	{
		result = PTSSH_ERR_CouldNotStartupSCP;
		goto error;
	}
	PTLOG((LL_debug3, "[PTssh] Read data. Len=%d, data=%u\n", pData->dataLen(), *(pData->getDataPtr())));

	delete pData;
	pData = NULL;

	//We are now ready to send the file data over
	return PTSSH_SUCCESS;

error:
	closeChannel(cNum);
	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::scpSendFinish(uint32 cNum)
{
	int32 result;

	//Validate channel number
	if ( ! m_pChannelMgr->isValidChannelNumber(cNum))
		return PTSSH_ERR_InvalidChannelNumber;

	/**** Send all requests *****/

	//Send End Of File
	PTLOG((LL_debug2, "[PTssh] Sending EOF on channel %d\n", cNum));
	result = channelSendEOF( cNum);
	if ( result != PTSSH_SUCCESS)
		return result;

	//Close the channel
	PTLOG((LL_debug2, "[PTssh] channel close on channel %d\n", cNum));
	result = closeChannel(cNum);
	if ( result != PTSSH_SUCCESS) {
		PTLOG((LL_error, "[scpSendFinish] Closing the channel failed with error %d\n", result));
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::scpReceiveInit(uint32 &cNum, struct stat &fileInfo, const char *pRemoteFilePath)
{
	int32 
		result;
	Data 
		*pData = NULL;
	char 
		scpCommand[] = "scp -pf ",
		tmp[1024],
		*pTmp = NULL;
	Data
		*pD = NULL;

	long int 
		recvMTimeUsec = 0,
		recvATimeUsec = 0;

	//Build the command to run
	memset(tmp, 0x0, 1024);
	memcpy(tmp, scpCommand, strlen(scpCommand));
	memcpy(tmp + strlen(scpCommand), pRemoteFilePath, strlen(pRemoteFilePath));

	//open a channel
	result = createChannel_session(cNum);
	if ( result != PTSSH_SUCCESS)
		return result;

	//call exec on the channel
	PTLOG((LL_debug1, "[PTssh] Requesting exec on channel %d\n", cNum));
	result = channelRequest_exec(cNum, tmp);
	if ( result != PTSSH_SUCCESS)
		goto error;

	PTLOG((LL_debug3, "[PTssh] Writing 0 byte on channel %d\n", cNum));
	result = channelWrite(cNum, "\0", 1);
	if ( result != PTSSH_SUCCESS)
		goto error;

	result = channelRead(cNum, &pD, true);
	if ( result != PTSSH_SUCCESS)
		goto error;

	//Inspect the response
	if ( pD && pD->dataLen() > 0)
	{
		char *pStr = (char*)pD->getDataPtr();
		pStr[pD->dataLen()] = 0;	//Put null terminator in place
		
		//Try and parse out the sizes
		if ( sscanf(pStr, "T%ld %ld %ld %ld", 
			&fileInfo.st_mtime, &recvMTimeUsec, &fileInfo.st_atime, &recvATimeUsec) != 4)
		{
			PTLOG((LL_error, "[PTssh] scpReceiveInit error: %s\n", pStr));
			pStr = NULL;
			delete pD;
			pD = NULL;

			return PTSSH_ERR_SCPReceiveInitFailure;
		}

		delete pD;
		pD = NULL;
	}
	else
	{
		PTLOG((LL_error, "[PTssh] scpReceiveInit: No data available\n"));

		return PTSSH_ERR_SCPReceiveInitFailure;
	}

	PTLOG((LL_debug3, "[PTssh] Writing 0 byte on channel %d\n", cNum));
	result = channelWrite(cNum, "\0", 1);
	if ( result != PTSSH_SUCCESS)
		goto error;

	result = channelRead(cNum, &pD, true);
	if ( result != PTSSH_SUCCESS)
		goto error;

	//Inspect the response
	if ( pD && pD->dataLen() > 0)
	{
		char *pStr = (char*)pD->getDataPtr();
		pStr[pD->dataLen()] = 0;	//Put null terminator in place
		
		//Try and parse out the sizes
		if ( sscanf(pStr, "C%d %ld ", &fileInfo.st_mode, &fileInfo.st_size) != 2)
		{
			PTLOG((LL_error, "[PTssh] scpReceiveInit error: %s\n", pStr));
			pStr = NULL;
			delete pD;
			pD = NULL;

			return PTSSH_ERR_SCPReceiveInitFailure;
		}

		delete pD;
		pD = NULL;
	}
	else
	{
		PTLOG((LL_error, "[PTssh] scpReceiveInit: No data available\n"));

		return PTSSH_ERR_SCPReceiveInitFailure;
	}

	PTLOG((LL_debug3, "[PTssh] Writing 0 byte on channel %d\n", cNum));
	result = channelWrite(cNum, "\0", 1);
	if ( result != PTSSH_SUCCESS)
		goto error;

	PTLOG((LL_debug3, "[PTssh] Scp recieve init: Preparing to recieve %s, %uB, %uKB, %uMB\n", 
		pRemoteFilePath, fileInfo.st_size, (fileInfo.st_size>>10), (fileInfo.st_size>>20)));

	return result;

error:
	PTLOG((LL_error, "Fuck\n"));
	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::scpReceiveFinish(uint32 cNum)
{
	int result = PTSSH_SUCCESS;

	//Validate channel number
	if ( ! m_pChannelMgr->isValidChannelNumber(cNum))
	{
		PTLOG((LL_error, "[PTssh] Tried to close an invalid channel\n"));
		return PTSSH_ERR_InvalidChannelNumber;
	}
	
	/**** Send all requests *****/

	//Send channel close
	PTLOG((LL_debug2, "[PTssh] channel close on channel %d\n", cNum));
	result = closeChannel(cNum);
	if ( result != PTSSH_SUCCESS){
		PTLOG((LL_error, "[PTssh] Failed to close channel %d\n", cNum));
	}
		
	return result;
}
#endif /* PTSSH_SCP */

/////////////////////////////////////////////////////////////////////////////////
////************** Static function *****************/
// void
//x11DefaultHandler( struct PTsshCallBackData *pCBD)
//{
//	//Do not delete the  struct PTsshCallBackData *pCBD!!! the PTssh class ownes it!
//	if ( pCBD && pCBD->pPTsshObject)
//	{
//		/* Lets get out of this static function and back in the context of our PTssh class.
//		* If you were an end developer also using C++ classes, I'd put a pointer to your
//		* class object in pCBD->pCallbackData, then you can cast that pointer into your
//		* class obj. */
//
//		if ( pCBD->pCallbackFunc == &x11DefaultHandler)
//		{
//			/* The callback function pointer matches PTssh's default handler, which is
//			* this function we are currently in. Run PTssh's handleX11Connection function */
//			pCBD->pPTsshObject->handleX11Connection( pCBD->channelNumber);
//		}
//		else if ( pCBD->pCallbackFunc)
//		{
//			//The user has specified their own function to handle X11 traffic, run it
//			(*(pCBD->pCallbackFunc))(pCBD);
//		}
//	}
//}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::handleX11Connection(uint32 channelNum)
{
	int32 result = PTSSH_SUCCESS;
	PTLOG((LL_debug1, "Woot! in PTssh::handleX11Connection\n"));

	/* We need to figure out if theres a X11 server running locally, if there is, accept the
	 * channel open request and handle the data. If not, send a channel failure confirmation */
	//Create a new tunnel handler
	X11TunnelHandler *pX11TH = new X11TunnelHandler(this, m_pChannelMgr);
	if ( pX11TH)
	{
		result = pX11TH->init(channelNum);
		if ( result != PTSSH_SUCCESS)
			return result;

		pthread_mutex_lock( &m_x11TunnelHandlerMutex);
			m_pX11Handlers->insertAtEnd( pX11TH);
		pthread_mutex_unlock( &m_x11TunnelHandlerMutex);
	}

	return result;
}

/////////////////////////////////////////////////////////////////////////////////
//char *
//PTssh::getLastErrorMsg()
//{
//	if ( m_pLastErrorMsg)
//		return strdup(m_pLastErrorMsg);
//
//	return NULL;
//}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::channelRead(uint32 channelNumber, Data **ppBuf, bool bIsBlockingRead, uint32 microsecTimeout, bool bExtendedData)
{
	BinaryPacket *pBP = NULL;
	int32 result = m_pChannelMgr->getInboundData(
		channelNumber,
		&pBP,
		bIsBlockingRead,
		microsecTimeout,
		bExtendedData);

	if ( result == PTSSH_SUCCESS && pBP)
	{
		/* Here we take advantage of the Data class inheriting directly from BinaryPacket.
		* This is only valid because Data does not contain any member variables of its own, it
		* simply adds on accessor methods. Thus we can cast it in this way. */
		*ppBuf = (Data *) pBP;
	}
	else
		*ppBuf = NULL;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::channelWrite(
		uint32 localChannelNumber,
		const char *pBuffer,
		uint32 bufferSize)
{
	/* IF you've read up on SSH and its channel window size or max packet size, this part
	 * is likely to raise your eyebrow. We don't worry about either window size or max
	 * packet size. We just go ahead and create a BP large enough to hold the entire 
	 * thing. We will let our SocketSend thread split this into multiple packets if it
	 * needs to. This should allow large writes to be queued up and sent more efficiently.
	 *   So we still pay attention to window size and max packet size, but we do it down
	 * lower in the bowls of PTssh! */
	int32 result;
	uint32 
		len =
			1 +				//byte      SSH_MSG_CHANNEL_DATA
			4 +				//uint32    recipient channel
			4 + bufferSize, //string    data
		remoteChannelNum;
	
	//Validate channel number
	if ( ! m_pChannelMgr->isValidChannelNumber(localChannelNumber))
		return PTSSH_ERR_InvalidChannelNumber;

	m_pChannelMgr->getRemoteChannelNumber(localChannelNumber, remoteChannelNum );

	//Allocate our packet
	BinaryPacket *pBP = new BinaryPacket(localChannelNumber);
	if (pBP && pBP->init(len) )
	{
		//Write the packet data
		pBP->writeByte( SSH_MSG_CHANNEL_DATA);
		pBP->writeUint32(remoteChannelNum);
		pBP->writeString( (char*)pBuffer, bufferSize);

		result = m_pChannelMgr->queueOutboundData(pBP);
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::getOptimalDataSize(uint32 localChannelNumber, uint32 &byteLength)
{
	int32 result = PTSSH_SUCCESS;
	byteLength = PTSSH_MAX_PACKET_SIZE;

	if ( m_pChannelMgr)
		result = m_pChannelMgr->getMaxPacketSizeRemote(localChannelNumber, byteLength);

	return result;
}

/*
///////////////////////////////////////////////////////////////////////////////
int32
PTssh::createChannel(uint32 &channelNumber, PTsshChannelType channelType)
{
	int32 
		result = PTSSH_SUCCESS;

	const char
		*pSession = "session",
		*pX11 = "x11";
	char 
		*pChannelType = NULL;

	channelNumber = PTSSH_BAD_CHANNEL_NUMBER;

	switch(channelType){
	case PTsshCT_session:
		pChannelType = (char*) pSession;
		break;
	case PTsshCT_x11:
		pChannelType = (char*) pX11;
		break;
	default:
		pChannelType = NULL;
	}

	if ( ! pChannelType)
		return PTSSH_ERR_InvalidType;

	uint32 
		len =
		1 +	                        //byte	SSH_MSG_CHANNEL_OPEN
		4 + strlen(pChannelType) +  //string    channel type in US-ASCII only
		4 +	                        //uint32    sender channel
		4 +	                        //uint32    initial window size
		4;	                        //uint32    maximum packet size
	
	//Create our packet
	BinaryPacket *pBP = new BinaryPacket();
	if (pBP && pBP->init(len) )
	{
		result = m_pChannelMgr->newChannel(PTSSH_DEFAULT_WINDOW_SIZE, PTSSH_MAX_PACKET_SIZE, channelType, channelNumber);
		if ( result != PTSSH_SUCCESS)
		{
			delete pBP;
			return result;
		}

		pBP->writeByte( SSH_MSG_CHANNEL_OPEN);
		pBP->writeString(pChannelType, (uint32)strlen(pChannelType));
		pBP->writeUint32( (uint32) channelNumber );
		pBP->writeUint32( PTSSH_DEFAULT_WINDOW_SIZE);
		pBP->writeUint32( PTSSH_MAX_PACKET_SIZE);

		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result == PTSSH_SUCCESS)
		{
			result = m_pChannelMgr->getChannelCreateResult( channelNumber);
			if ( result != PTSSH_SUCCESS)
				m_pChannelMgr->deleteChannel( channelNumber, false);
		}
		else
		{
			delete pBP;
			result = PTSSH_ERR_CouldNotQueuePacketForSending;
		}
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}*/


///////////////////////////////////////////////////////////////////////////////
int32
PTssh::channelSendEOF(uint32 localChannelNumber)
{
	int32 result;
	uint32 
		len =
			1 +		//byte SSH_MSG_CHANNEL_EOF
			4,		//uint32 recipient channel
		remoteChannelNum;
	
	//Validate channel number
	if ( ! m_pChannelMgr->isValidChannelNumber(localChannelNumber))
		return PTSSH_ERR_InvalidChannelNumber;

	m_pChannelMgr->getRemoteChannelNumber(localChannelNumber, remoteChannelNum );

	//Allocate our packet
	BinaryPacket *pBP = new BinaryPacket(localChannelNumber);
	if (pBP && pBP->init(len) )
	{
		pBP->writeByte( SSH_MSG_CHANNEL_EOF);
		pBP->writeUint32( remoteChannelNum );
		
		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result != PTSSH_SUCCESS)
			delete pBP;
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTssh::setServiceType( PTsshServiceType serviceType)
{
	int32 
		result = PTSSH_SUCCESS;
	if ( m_serviceType == serviceType)
		return 1;

	char 
		*pStr = NULL,
		sshUserAuth[]	= "ssh-userauth",
		sshConnection[] = "ssh-connection";

	switch (serviceType){
		case PST_Connection:
			pStr = sshConnection;
			break;
		case PST_UserAuth:
			pStr = sshUserAuth;
			break;
	}

	if ( ! pStr)
		return PTSSH_ERR_InvalidType;

	//Ok, we need to send a service request to get the type updated for a furutre request
	uint32
		len = 
			1 + 
			4 + (uint32) strlen( pStr);

	PTLOG((LL_debug2, "Sending a set service request\n"));
	BinaryPacket *pBP = new BinaryPacket();
	if (pBP && pBP->init(len) )
	{
		pBP->writeByte(SSH_MSG_SERVICE_REQUEST);
		pBP->writeString( pStr, (uint32) strlen( pStr));

		result = m_pChannelMgr->queueOutboundData(pBP);
		if ( result != PTSSH_SUCCESS)
			delete pBP;

		result = m_pTransport->getServiceResult();
		if ( result == PTSSH_SUCCESS)
		{
			m_serviceType = serviceType;
			return result;
		}
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}
