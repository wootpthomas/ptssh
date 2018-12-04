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

#ifdef WIN32
#   include <winsock2.h>

	//Redefine the close() function on windows so we don't break on linux
#   define close(SOCKET)				closesocket(SOCKET)
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

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <ctype.h>


#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif

#include "PTsshConfig.h"
#include "PTsshSocket.h"
#include "SSH2Types.h"
#include "Utility.h"
#include "SocketSend.h"
#include "SocketRecieve.h"
#include "Transport.h"
#include "ChannelManager.h"
#include "CryptoStuff.h"
#include "BinaryPacket.h"
#include "Queue.h"
#include "Compress.h"
#include "PTsshLog.h"

///////////////////////////////////////////////////////////////////////////////
PTsshSocket::PTsshSocket(
		ChannelManager *pChannelMgr,
	    Transport *pTransport,
		pthread_mutex_t *pActivityMutex,
		pthread_cond_t *pActivity_cv,
		char * address, 
		uint16 port):
m_pChannelMgr(pChannelMgr),
m_pTransport(pTransport),
m_pActivityMutex(pActivityMutex),
m_pActivity_cv(pActivity_cv),
m_port( port),
m_bRecievedBanner(false),
m_pHostKey(0),
m_pRemoteBanner(0),
m_remoteBannerLen(0),
m_blockSizeOut(8),
m_macSizeOut(0),
m_bIsSocketAlive(false),
m_bWasSocketDisconnected(false),
m_pSS(0),
m_pSR(0),
m_pSockAddr(0),
m_pCrypto(0),
m_pInboundQ(0),
m_pStrKeyX(0),
m_pStrHostKey(0),
m_pStrEncryptCtoS(0),
m_pStrEncryptStoC(0),
m_pStrMacCtoS(0),
m_pStrMacStoC(0),
m_pStrCompCtoS(0),
m_pStrCompStoC(0)
{
	//Seed our random number generator
	srand( (uint32) time(NULL) );

	//Copy the address string
	m_pAddress = strdup(address);

	for (uint8 ctr = 0; ctr < 10; ctr++)
	{
		m_pClient_kex[ctr] = 0;
		m_pRH_kex[ctr] = 0;
	}

	//Set our types all to invalid or none
	m_KN_keyx = KEYX_dh_unknown;	/**< Agreed upon algorithms for key exchange */

	m_KN_hostKey = HOST_invalid;

	m_KN_encrypt_CtoS = ENC_none;
	m_KN_encrypt_StoC = ENC_none;

	m_KN_mac_CtoS = MAC_none;
	m_KN_mac_StoC = MAC_none;

	m_KN_comp_CtoS = COMP_none;
	m_KN_comp_StoC = COMP_none;

#ifdef _DEBUG
	PTLOG((LL_debug1, "[PS] The buffer size for incoming socket reads is %d bytes\n", PTSSH_MAX_RAW_BUF_IN_SIZE));
#endif
}

///////////////////////////////////////////////////////////////////////////////
PTsshSocket::~PTsshSocket(void)
{
	for (uint8 ctr = 0; ctr < 10; ctr++)
	{
		if (m_pRH_kex[ctr])
		{
			delete m_pRH_kex[ctr];
			m_pRH_kex[ctr] = NULL;
		}

		if (m_pClient_kex[ctr])
		{
			delete m_pClient_kex[ctr];
			m_pClient_kex[ctr] = NULL;
		}
	}

	if (m_pAddress)
	{
		delete m_pAddress;
		m_pAddress = NULL;
	}

	if (m_pRemoteBanner)
	{
		delete m_pRemoteBanner;
		m_pRemoteBanner = NULL;
	}

	if (m_pSockAddr)
	{
		delete m_pSockAddr;
		m_pSockAddr = NULL;
	}

	if (m_pCrypto)
	{
		delete m_pCrypto;
		m_pCrypto = NULL;
	}

	if (m_pInboundQ)
	{
		delete m_pInboundQ;
		m_pInboundQ = NULL;
	}

	if (m_pSS)
	{
		delete m_pSS;
		m_pSS = NULL;
	}

	if (m_pSR)
	{
		delete m_pSR;
		m_pSR = NULL;
	}

	pthread_mutex_destroy( &m_inboundQMutex);
	pthread_mutex_destroy( &m_isAliveMutex);

	m_pTransport = NULL;
	m_pChannelMgr = NULL;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTsshSocket::init()
{
	int32 result;
	//Init our mutexes
	if ( pthread_mutex_init( &m_inboundQMutex, 0) != 0)
		goto error;
	if ( pthread_mutex_init( &m_isAliveMutex, 0) != 0)
		goto error;

	m_pSockAddr = new struct sockaddr_in;
	if ( ! m_pSockAddr)
		goto error;

	//Create our socket
	m_sock = PTSSH_BAD_SOCKET_NUMBER;
	result = createSocket( m_sock, m_pSockAddr, m_pAddress, m_port, false);
	if ( result != PTSSH_SUCCESS)
		goto error;

	result = PTSSH_ERR_CouldNotAllocateMemory;

	//Create our diffie-hellman object
	m_pCrypto = new CryptoStuff(this);
	if ( ! m_pCrypto)
		goto error;

	//Fill our supported kex array
	m_pClient_kex[0] = strdup(PTSSH_KEYX_ALGORITHMS);
	m_pClient_kex[1] = strdup(PTSSH_PUBKEY_ALGORITHMS);
	m_pClient_kex[2] = strdup(PTSSH_ENC_ALGORITHMS);
	m_pClient_kex[3] = strdup(PTSSH_ENC_ALGORITHMS);
	m_pClient_kex[4] = strdup(PTSSH_MAC_ALGORITHMS);
	m_pClient_kex[5] = strdup(PTSSH_MAC_ALGORITHMS);
	m_pClient_kex[6] = strdup(PTSSH_COMPRESSION_ALG);
	m_pClient_kex[7] = strdup(PTSSH_COMPRESSION_ALG);
	m_pClient_kex[8] = strdup(PTSSH_LANGUAGES);
	m_pClient_kex[9] = strdup(PTSSH_LANGUAGES);

	m_pInboundQ = new Queue();
	if ( ! m_pInboundQ)
		goto error;
	if ( m_pInboundQ->init() != PTSSH_SUCCESS)
		goto error;

	result = PTSSH_SUCCESS;
	return result;

error:


	if ( m_pCrypto )
	{
		delete m_pCrypto;
		m_pCrypto = NULL;
	}

	if ( m_pInboundQ )
	{
		delete m_pInboundQ;
		m_pInboundQ = NULL;
	}

	if ( m_pSockAddr )
	{
		delete m_pSockAddr;
		m_pSockAddr = NULL;
	}

	if ( m_sock != PTSSH_BAD_SOCKET_NUMBER)
		close(m_sock);

	return result;
}

///////////////////////////////////////////////////////////////////////////////
bool
PTsshSocket::isAlive()
{
	/* Check the SocketSend and SocketRecieve threads, if they are still running, then
	 * we consider the socket to still be alive. This also helps us in the case that
	 * the SocketSend thread shut down because it sent the disconnect message, but
	 * SocketRecieve still has a few paakcets to finish processing. */
	return m_pSS->isRunning() || m_pSR->isRunning();
}

///////////////////////////////////////////////////////////////////////////////
bool
PTsshSocket::isDisconnected( int32 &socketError)
{
	int32
		errCodeSS = 0,
		errCodeSR = 0,
		socketErrSS = 0,
		socketErrSR = 0;

	/* First, check the SocketSend thread. If we sent a disconnect message, then
	 * we assume the disconnect is normal and expected */
	if ( m_pSS->bWasDisconnectSent() )
		return false;

	/* Next we check the SocketRecieve thread. If we recieved a disconnect message, then
	 * we assume the disconnect is normal and expected */
	if ( m_pSR->bWasDisconnectRecieved() )
		return false;

	if ( m_pSS->socketShutdownStatus( errCodeSS, socketErrSS) ){
		PTLOG((LL_debug3, "[PS] SocketSend errCode %d, socketError %d\n", errCodeSS, socketErrSS));
	}
	if ( m_pSR->socketShutdownStatus( errCodeSR, socketErrSR) ){
		PTLOG((LL_debug3, "[PS] SocketRecieve errCode %d, socketError %d\n", errCodeSR, socketErrSR));
	}

	if ( socketErrSS != 0)
		socketError = socketErrSS;
	else if ( socketErrSR != 0)
		socketError = socketErrSR;

	return true;
}

///////////////////////////////////////////////////////////////////////////////
void
PTsshSocket::getAlgs( ALG_Type type, char **ppList)
{
	if ( type < 0 || type > ALG_lang_StoC)
		*ppList = NULL;
	else
		*ppList = strdup(m_pClient_kex[type]);
}

///////////////////////////////////////////////////////////////////////////////
bool
PTsshSocket::setAlgs( ALG_Type type, char *pList)
{
	if ( type < 0 || type > ALG_lang_StoC)
		return false;

	if ( m_pClient_kex[type])
		delete m_pClient_kex[type];
	m_pClient_kex[type] = pList;

	return true;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTsshSocket::getCompressionObj(bool bIsClientToServer, Compress **ppComp)
{
	int32 result = PTSSH_SUCCESS;
	COMP_Type compType =
		bIsClientToServer? m_KN_comp_CtoS : m_KN_comp_StoC;

	*ppComp = NULL;

	/* If the day comes that we finally have another compression algorithm
	 * to use besides zlib, then we'll make a base Compression class and make
	 * our zlib "Compress" class inherit from it... */
	switch (compType) {
#if defined(PTSSH_ZLIB) || defined(PTSSH_ZLIB_OPENSSH)
		case COMP_zlib:
		case COMP_zlib_openssh:
			*ppComp = new Compress();
			if ( ! *ppComp)
				result = PTSSH_ERR_CouldNotAllocateMemory;
			else
				result = (*ppComp)->init(bIsClientToServer);
			break;
#endif /* PTSSH_ZLIB */
		case COMP_none:
			//Leave object NULL
			break;
		default:
			result = PTSSH_FAILURE;
			PTLOG((LL_error, "[PS]: invalid compression type %d specified\n", m_KN_comp_CtoS));
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
bool
PTsshSocket::isCompressionEnabled(bool bIsClientToServer)
{
	if ( bIsClientToServer && 
		(m_KN_comp_CtoS != COMP_none || m_KN_comp_CtoS != COMP_invalid))
	{
		return true;
	}
	else if (m_KN_comp_StoC != COMP_none || m_KN_comp_StoC != COMP_invalid)
		return true;

	return false;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTsshSocket::connectToServer()
{
	int
		result = PTSSH_SUCCESS;
	bool
		bSS_init = false,
		bSR_init = false;

	CryptoStuff::Cipher 
		*pEncrypt = NULL,
		*pDecrypt = NULL;

	//Set socket options
	setSocketOptions(m_sock);

	//Let's try and connect to the host with our socket
	if ( ::connect(m_sock, (struct sockaddr*)m_pSockAddr, sizeof(struct sockaddr_in)) != 0) {
		close(m_sock);

#ifdef WIN32
		int error = WSAGetLastError();
		PTLOG((LL_error, "Winsock error number %d\n", error));
#endif
		result = PTSSH_ERR_CouldNotConnectToHost;
		goto error;
	}

	/**************************
	* Object init and member var setup
	***************************/
	
	pthread_mutex_lock( &m_isAliveMutex);
		m_bIsSocketAlive = true;
	pthread_mutex_unlock( &m_isAliveMutex);

	//Now set the socket blocking
	if (! setSocketBlocking(m_sock, true)) //Blocking
	{
		result = PTSSH_ERR_CouldNotSetSocketBlocking;
		goto error;
	}

	//Finally, create and startup our socket send and socket recieve threads
	m_pSS = new SocketSend(m_pChannelMgr, m_pActivityMutex, m_pActivity_cv, this, m_sock);
	m_pSR = new SocketRecieve(m_pChannelMgr, m_pActivityMutex, m_pActivity_cv, this, m_sock);
	if ( ! m_pSR || ! m_pSS)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

	if ( m_pSS->init() != PTSSH_SUCCESS)
	{
		result = PTSSH_ERR_CouldNotInit_SS;
		goto error;
	}
	bSS_init = true;

	if ( m_pSR->init() != PTSSH_SUCCESS)
	{
		result = PTSSH_ERR_CouldNotInit_SR;
		goto error;
	}
	bSR_init = true;

	/* Now let the SocketRecieve class know about the SocketSend class so that it can tell
	 * it when to go into key exchange mode. */
	m_pSR->setSocketSendPtr( m_pSS);

	/* ...and let the SocketSend class know about the SocketRecieve class so that it can
	 * tell it when keyX mode is finished & when it can use its new cipher object */
	m_pSS->setSocketRecievePtr( m_pSR);

	/* Create our initial Cipher objects. Starting out, they won't have a cipher algorithm,
	so we'll just use them to get things like blocksize and mac size */
	pEncrypt = new CryptoStuff::Cipher();
	if ( ! pEncrypt)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}
	
	//Give the new cipher to the socketSend class
	m_pSS->setInitialCipher( pEncrypt);
	pEncrypt = NULL; // m_pSS now ownes this

	pDecrypt = new CryptoStuff::Cipher();
	if ( ! pDecrypt)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

	//Set the new decryption cipher
	m_pSR->setInitialCipher( pDecrypt);
	pDecrypt = NULL; //m_pSR now ownes this

	/***************************
	* Send/Recieve Banners
	***************************/
	//setV_C, our banner message in our DH object
	m_pCrypto->setV_C( PTSSH_BANNER, (uint32) strlen(PTSSH_BANNER) -2);
	
	//Send our banner 
	if ( rawSocketWrite( PTSSH_BANNER, (uint32) strlen(PTSSH_BANNER)) == PTSSH_SUCCESS)
	{
		char banner[256];
		memset(banner, 0x0, 256);
		//recieve remote banner
		int32 len = readBanner( &m_pRemoteBanner);
		if (len > 0 && m_pRemoteBanner)
		{
			memcpy(banner, m_pRemoteBanner, len); //  <-- dangerous!
			PTLOG((LL_debug1, "Remote banner: %s\n", banner));
		}
		else
		{
			result = PTSSH_ERR_CouldNotGetRemoteBanner;
			goto error;
		}
	}

	/***************************
	* Start the threads!
	***************************/
	if ( ! m_pSS->startThread())
	{
		result = PTSSH_ERR_CouldNotStartSocketSendThread;
		goto error;
	}
	if ( ! m_pSR->startThread())
	{
		result = PTSSH_ERR_CouldNotStartSocketRecieveThread;
		goto error;
	}
	
	return result;

error:
	close (m_sock);
	if ( m_pSS)
	{
		if ( bSS_init && m_pSS->isRunning())
			m_pSS->stopThread();

		delete m_pSS;
		m_pSS = NULL;
	}

	if ( m_pSR)
	{
		if ( bSR_init && m_pSR->isRunning() )
			m_pSR->stopThread();

		delete m_pSR;
		m_pSR = NULL;
	}

	if ( pEncrypt )
	{
		m_pSS->setCipher( NULL);
		delete pEncrypt;
		pEncrypt = NULL;
	}

	if ( pDecrypt )
	{
		m_pSR->setCipher( NULL);
		delete pDecrypt;
		pDecrypt = NULL;
	}

	pthread_mutex_lock( &m_isAliveMutex);
		m_bIsSocketAlive = false;
	pthread_mutex_unlock( &m_isAliveMutex);

	return result;
}

///////////////////////////////////////////////////////////////////////////////
/*
name-list
uint32 followed by the names, comma seperated.
*/
int32
PTsshSocket::negotiateEncryptions(BinaryPacket **pBP_kexinit)
{
	/* Each side starts by sending the following packet....
	We build the packet to let our server know what authentication crap we support	*/
	int binaryPackLen = 0,
		payloadLen = 
		1 +										//byte         SSH_MSG_KEXINIT
		16 +									//byte[16]     cookie (random bytes)
		4 + (uint32) strlen( PTSSH_KEYX_ALGORITHMS) +		//name-list    kex_algorithms
		4 + (uint32) strlen( PTSSH_PUBKEY_ALGORITHMS) +	//name-list    server_host_key_algorithms
		4 + (uint32) strlen( PTSSH_ENC_ALGORITHMS) +		//name-list    encryption_algorithms_client_to_server
		4 + (uint32) strlen( PTSSH_ENC_ALGORITHMS) +		//name-list    encryption_algorithms_server_to_client
		4 + (uint32) strlen( PTSSH_MAC_ALGORITHMS) +		//name-list    mac_algorithms_client_to_server
		4 + (uint32) strlen( PTSSH_MAC_ALGORITHMS) +		//name-list    mac_algorithms_server_to_client
		4 + (uint32) strlen(PTSSH_COMPRESSION_ALG) +		//name-list    compression_algorithms_client_to_server
		4 + (uint32) strlen(PTSSH_COMPRESSION_ALG) +		//name-list    compression_algorithms_server_to_client
		4 + (uint32) strlen(PTSSH_LANGUAGES) +			//name-list    languages_client_to_server
		4 + (uint32) strlen(PTSSH_LANGUAGES) +			//name-list    languages_server_to_client
		1 +										//boolean      first_kex_packet_follows
		4;										//uint32       0 (reserved for future extension)
	
	int32
		result = PTSSH_SUCCESS;
	uint32 
		packLen;
	uint8 
		padLen;
	char 
		*pBuf = NULL;

	BinaryPacket *pBP = new BinaryPacket();
	if ( ! pBP)
		return PTSSH_ERR_CouldNotAllocateMemory;

	if ( ! pBP->init(payloadLen) )
	{ 
		result = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

	//Build the client's SSH_MSG_KEXINIT BinaryPacket
	buildKeyExchangePacket( pBP);

	//Set I_C, the payload of the client's SSH_MSG_KEXINIT
	/* This should be just the payload, no padding included. Starts with the SSH_MSG* byte
	and ends with the last reserved byte */
	m_pCrypto->setI_C( (char*) pBP->getPayloadPtr(), pBP->getPayloadLen());

	//Give our crypto object the rest of the info it needs to build the secret and exchange hash (sessionID)
	// setV_C <- this was set in PTsshSocket::connect()
	// setV_S <- this was set in PTsshSocket::readBanner()
	// setI_C <- this was set above
	// setI_S <- this was set a few lines below

	//Send off our packet to the remote end, m_pSS will delete the packet after its done
	result = m_pChannelMgr->queueOutboundData( pBP);
	if ( result != PTSSH_SUCCESS)
		goto error;

	pBP = NULL;

	//Get a pointer to the packet's raw data
	pBuf = (char*) (*pBP_kexinit)->getBP();

	//Set the I_S, the payload of the server's SSH_MSG_KEXINIT
	packLen = PTSSH_htons32( *((uint32*)pBuf));
	padLen = *(pBuf+4);
	m_pCrypto->setI_S( pBuf+5, packLen - padLen -1 );

	//This will get all details from the packet
	result = parseHostKeyExchangePacket( pBuf);
	if (result != PTSSH_SUCCESS)
	{
		result = PTSSH_ERR_CouldNotParseHostKeyExchangePacket;
		goto error;
	}

	//We are done with the KeyX packet, delete it
	if ( *pBP_kexinit)
	{
		delete *pBP_kexinit;
		*pBP_kexinit = NULL;
	}

	//Do the rest of the keyx
	return result;

error:
	if ( pBP)
		delete pBP;

	if ( *pBP_kexinit)
	{
		delete *pBP_kexinit;
		*pBP_kexinit = NULL;
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTsshSocket::enqueueInboundPacket( BinaryPacket * pPacket)
{
	return m_pInboundQ->enqueue( pPacket);
}

///////////////////////////////////////////////////////////////////////////////
BinaryPacket* 
PTsshSocket::dequeueInboundPacket()
{
	return m_pInboundQ->dequeue();
}

///////////////////////////////////////////////////////////////////////////////
void
PTsshSocket::buildKeyExchangePacket( BinaryPacket *pBP)
{
	//Put SSH_MSG in place
	pBP->writeByte( SSH_MSG_KEXINIT);
	
	//Fill next 16 bytes with random shit
	for (uint8 i = 0; i < 16; i++)
#ifdef _DEBUG
		pBP->writeByte( i );
#else
		pBP->writeByte( rand() %256);
#endif

	//Fill in kex_algorithms
	pBP->writeString(PTSSH_KEYX_ALGORITHMS, (uint32) strlen( PTSSH_KEYX_ALGORITHMS));

	//Fill in server_host_key_algorithms
	pBP->writeString(PTSSH_PUBKEY_ALGORITHMS, (uint32) strlen(PTSSH_PUBKEY_ALGORITHMS));

	//Fill in encryption_algorithms_client_to_server
	pBP->writeString(PTSSH_ENC_ALGORITHMS, (uint32) strlen(PTSSH_ENC_ALGORITHMS));
	
	//Fill in encryption_algorithms_server_to_client
	pBP->writeString(PTSSH_ENC_ALGORITHMS, (uint32) strlen(PTSSH_ENC_ALGORITHMS));

	//Fill in mac_algorithms_client_to_server
	pBP->writeString(PTSSH_MAC_ALGORITHMS, (uint32) strlen(PTSSH_MAC_ALGORITHMS));

	//Fill in mac_algorithms_server_to_client
	pBP->writeString(PTSSH_MAC_ALGORITHMS, (uint32) strlen(PTSSH_MAC_ALGORITHMS));

	//Fill in compression_algorithms_client_to_server
	pBP->writeString(PTSSH_COMPRESSION_ALG, (uint32) strlen(PTSSH_COMPRESSION_ALG));

	//Fill in compression_algorithms_server_to_client
	pBP->writeString(PTSSH_COMPRESSION_ALG, (uint32) strlen(PTSSH_COMPRESSION_ALG));

	//Fill in languages_client_to_server
	pBP->writeString(PTSSH_LANGUAGES, (uint32) strlen(PTSSH_LANGUAGES));

	//Fill in languages_server_to_client
	pBP->writeString(PTSSH_LANGUAGES,(uint32)  strlen(PTSSH_LANGUAGES));

	//Fill in first kex packet
	pBP->writeBoolean( false);

	//Write reserved uint32
	pBP->writeUint32( 0);
}

///////////////////////////////////////////////////////////////////////////////
int32
PTsshSocket::parseHostKeyExchangePacket( char *pBP)
{
	int32
		result = PTSSH_SUCCESS;
	char 
		*pIter = pBP + 5;
	uint32
		size;

	//Make sure its the right type
	if (*pIter != SSH_MSG_KEXINIT)
		return PTSSH_ERR_CouldNotParseHostKeyExchangePacket;

	//Move our pointer to the kex_algorithms
	pIter += 17;

	/* This takes and copies the data from the "remote host's" key exchange packet
	 * into our m_pRH_kex array. Memory is allocated, or freed and deleted as needed.
	 * the array will hold something like:
	 m_pRH_kex[0] diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,
	 	diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
	 m_pRH_kex[1] ssh-rsa,ssh-dss
	 m_pRH_kex[2] aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour128,arcfour256,
	 	arcfour,aes192-cbc,aes256-cbc,rijndael-cbc@lysator.liu.se,aes128-ctr,aes192-ctr,
		aes256-ctr
	 m_pRH_kex[3] aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour128,arcfour256,
	 	arcfour,aes192-cbc,aes256-cbc,rijndael-cbc@lysator.liu.se,aes128-ctr,aes192-ctr,
		aes256-ctr
	 m_pRH_kex[4] ihmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160,
	 	hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96
	 m_pRH_kex[5] ihmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160,
	 	hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96
	 m_pRH_kex[6] none,zlib@openssh.com,zlib
	 m_pRH_kex[7] none,zlib@openssh.com,zlib
	 m_pRH_kex[8]
	 m_pRH_kex[9]
	 */
	for (uint8 ctr = 0; ctr < 10; ctr++)
	{
		PTSSH_htons32( *(uint32*)pIter, &size );
		if ( ! reallocate( &m_pRH_kex[ctr], size+1) )
			return PTSSH_ERR_CouldNotAllocateMemory;
		pIter += 4;
		memcpy(m_pRH_kex[ctr], pIter, size);
		m_pRH_kex[ctr][size] = 0;	//NULL terminate
		pIter += size;
	}

	//Now let's figure out what algorithms to use, 0-7, don't bother with languages
	for (uint8 ctr = 0; ctr < 8; ctr++)
	{
		/* First we make a client of the algorithms that we are going to compare.
		 * we have to make a copy because strtok will dork with the original
		 * strings otherwise */
		char
			*pCopyClientAlgs = strdup(m_pClient_kex[ctr]),
			*pCopyServerAlgs = strdup(m_pRH_kex[ctr]),
			*pClient = NULL,
			*pServer = NULL;
		bool
			bMatchFound = false;
		int
			CSAlgsLen = (uint32)strlen(pCopyServerAlgs);

		if ( ! pCopyClientAlgs || ! pCopyServerAlgs)
		{
			if ( pCopyClientAlgs)
				delete pCopyClientAlgs;
			if ( pCopyServerAlgs)
				delete pCopyServerAlgs;
			return PTSSH_ERR_CouldNotAllocateMemory;
		}

		//Take our string copy of our server algs and replace any ',' with NULLs
		for (int i = 0; i < CSAlgsLen; i++)
		{
			if ( pCopyServerAlgs[i] == ',')
			{
				pCopyServerAlgs[i] = 0x0;
			}
		}

		pClient = strtok(pCopyClientAlgs, ",");
		while( pClient && ! bMatchFound)
		{
			//Point to the first server alg
			pServer = pCopyServerAlgs;
			while( pServer && (*pServer) && ! bMatchFound)
			{
				if (strcmp(pServer, pClient) == 0 )
				{
					bMatchFound = true;
					switch(ctr){
						case 0:
							m_KN_keyx = setAlgKeyX(pClient);
							break;
						case 1:
							m_KN_hostKey = setAlgPublicKey(pClient);
							break;
						case 2:
							m_KN_encrypt_CtoS = setAlgEncryption(pClient);
							break;
						case 3:
							m_KN_encrypt_StoC = setAlgEncryption(pClient);
							break;
						case 4:
							m_KN_mac_CtoS = setAlgHmac(pClient);
							break;
						case 5:
							m_KN_mac_StoC = setAlgHmac(pClient);
							break;
						case 6:
							m_KN_comp_CtoS = setAlgCompression(pClient);
							break;
						case 7:
							m_KN_comp_StoC = setAlgCompression(pClient);
							break;
						/* We don't care about languages just yet */
					}
				}
				else
				{
					//Point to the next server algorithm
					//Is there another one?
					pServer += strlen(pServer);
					if ( pServer < pCopyServerAlgs + CSAlgsLen)
						pServer += 1; //Move past NULL to next string
				}
			}

			pClient = strtok(NULL, ",");
		}
		
		if ( pCopyClientAlgs)
			delete pCopyClientAlgs;
		if ( pCopyServerAlgs)
			delete pCopyServerAlgs;
	}

	return PTSSH_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
/*
0x005C6048  53 53 48 2d 32 2e 30 2d 4f 70 65 6e 53 53 48 5f 34 2e 33 0a  SSH-2.0-OpenSSH_4.3.
0x005C605C  00 00 02 bc 07 14 75 8b 13 fa 8e 5c 0f aa 9f 5c 96 61 26 46  ......u..??\.??\?a&F
0x005C6070  18 10 00 00 00 59 64 69 66 66 69 65 2d 68 65 6c 6c 6d 61 6e  .....Ydiffie-hellman
0x005C6084  2d 67 72 6f 75 70 2d 65 78 63 68 61 6e 67 65 2d 73 68 61 31  -group-exchange-sha1
*/
int32
PTsshSocket::readBanner(char **pBuf)
{
	int 
		bytesRead;
	bool
		bValidBanner = false;

	char *pTmp = new char[PTSSH_SOCKET_BUF_LEN];
	if ( ! pTmp)
	{
		//Couldn't allocate ram!!
		return PTSSH_ERR_CouldNotAllocateMemory;
	}

	bool foundBanner = false;
#ifdef WIN32
	int error = WSAEWOULDBLOCK;
#else
	int error = EAGAIN;
#endif
	do {
		bytesRead = recv(m_sock, pTmp, PTSSH_SOCKET_BUF_LEN, MSG_PEEK);
		if ( bytesRead <= 0)
		{
#ifdef WIN32
		error = WSAGetLastError();
#else
		error = errno;
#endif
		}

		//Make sure we read out something in banner format
		if (bytesRead > 9)
		{
			for (int i = 8; i < bytesRead; i++)
			{
				if ( (pTmp[i] == '\r' && pTmp[i+1] == '\n') || pTmp[i] == '\n')
				{
					foundBanner = true;
					break;
				}
			}
		}
#ifdef WIN32
	} while (error == WSAEWOULDBLOCK && ! foundBanner);
#else
   } while (error == EAGAIN && ! foundBanner);
#endif

	//Let's see if this is our banner message
	if ( bytesRead < 9)
		return PTSSH_ERR_CouldNotReadRemoteBanner;

	// SSH-2.0-
	if ( memcmp(pTmp, "SSH-2.0-", 8) == 0)
		bValidBanner = true;
	else if ( memcmp(pTmp, "SSH-1.99-", 9) == 0)
		bValidBanner = true;

	if (bValidBanner)
	{
		for (int i = 8; i < bytesRead; i++)
		{
			if ( pTmp[i] == '\r' && pTmp[i+1] == '\n')
			{
				//This fits our banner format, read it out of the socket's buffer
				bytesRead = recv(m_sock, pTmp, i+2, 0);
				*pBuf = pTmp;

				m_pCrypto->setV_S(pTmp, bytesRead-2);
				return bytesRead - 2;
			}
			else if ( pTmp[i] == '\n')
			{
				//This fits our banner format, read it out of the socket's buffer
				bytesRead = recv(m_sock, pTmp, ++i, 0);
				*pBuf = pTmp;

				m_pCrypto->setV_S(pTmp, bytesRead-1);
				return bytesRead - 1;
			}
		}
	}

	return PTSSH_ERR_CouldNotReadRemoteBanner;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTsshSocket::doKeyExchange_step1()
{
	int32
		payloadSize = 0,
		returnVal = PTSSH_SUCCESS;		//Set to success

	BinaryPacket
		*pBP = NULL;
	
	//Set the key exchange type
	if ( ! m_pCrypto->setKeyExchangeType( m_KN_keyx))
	{
		returnVal = PTSSH_ERR_CouldNotSetKeyExchangeType;
		goto error;
	}

	//Compute E
	if ( ! m_pCrypto->compute_E())
	{
		returnVal = PTSSH_ERR_CouldNotCompute_E;
		goto error;
	}

	//Make the SSH2_MSG_KEXDH_INIT message
	// Message type (1) + mpint size (4) + bignum bytes (eBytes)
	payloadSize = 1 + 4 + m_pCrypto->getE_byteCount();
	pBP = new BinaryPacket();
	if ( ! pBP)
	{
		returnVal = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}
	
	if ( ! pBP->init(payloadSize) )
	{
		returnVal = PTSSH_ERR_CouldNotCreateBinaryPacket;
		goto error;
	}
	
	pBP->writeByte( SSH_MSG_KEXDH_INIT);		//Set message type
	pBP->writeMPint( m_pCrypto->getE() );			//Write in "e"

	//Send off our SSH2_MSG_KEXDH_INIT
	returnVal = m_pChannelMgr->queueOutboundData( pBP);
	if ( returnVal != PTSSH_SUCCESS)
		goto error;

	PTLOG((LL_debug1, "Sent SSH2_MSG_KEXDH_INIT\n"));
	return returnVal;

error:
	if ( pBP)
		delete pBP;

	return returnVal;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTsshSocket::doKeyExchange_step2(BinaryPacket **ppBP)
{
	struct CryptoStuff::Cipher
		*pEncrypt = NULL,
		*pDecrypt = NULL;
	
	char
		*pIter = NULL;
	
	int32
		payloadSize = 0,
		returnVal = PTSSH_SUCCESS;		//Set to success
	uint32
		hSigLen,
		fSize;
	
	BinaryPacket
		*pBP = NULL;

	//Parse out and let our DH object handle the public key / certificate stuff
	//Set the server's host key
	pIter = (char*)(*ppBP)->getBP();
	pIter += 6;
	int hostKeySize = PTSSH_htons32(*(uint32*)(pIter));
	pIter += 4;
	if ( ! m_pCrypto->setK_S(pIter, hostKeySize))
	{
		returnVal = PTSSH_ERR_CouldNotSet_K_S;
		goto error;
	}

	/* At this point, the server's Host key fingerprint is now set */

	if ( ! m_pCrypto->setPublicKey(pIter, hostKeySize) )
	{
		returnVal = PTSSH_ERR_CouldNotSetPublicKey;
		goto error;
	}

	pIter += hostKeySize;

	//Parse out and set f
	fSize = PTSSH_htons32(*(uint32*)(pIter));
	pIter += 4;
	m_pCrypto->setF_andComputeSharedSecret( (unsigned char*)pIter, fSize);
	pIter += fSize;

	//Parse out and set the "signature of H"
	hSigLen = PTSSH_htons32(*(uint32*)(pIter));
	pIter += 4;
	if ( ! m_pCrypto->setSignatureOfH( pIter, hSigLen))
	{
		returnVal = PTSSH_ERR_CouldNotSetSignatureOf_H;
		goto error;
	}
	
	//Alrighty, compute the hash/sessionID
	if ( ! m_pCrypto->computeSessionID())
	{
		returnVal = PTSSH_ERR_CouldNotComputeSessionHash;
		goto error;
	}

	if ( ! m_pCrypto->verifySigOfH_onTheBigHash())
	{
		PTLOG((LL_error, "FAILED to veryify signature of H\n"));
		returnVal = PTSSH_ERR_CouldNotVerifySignatureOf_H;
		goto error;
	}
	PTLOG((LL_debug2, "Verified signature of H\n"));

	//Alright, we are done with the SSH_MSG_KEXDH_REPLY packet, delete it
	delete *ppBP;
	*ppBP = NULL;

	//Now send our SSH_MSG_NEWKEYS to let the remote side know that we are ready
	//Make the SSH_MSG_NEWKEYS message
	payloadSize = 1;
	pBP = new BinaryPacket();
	if ( ! pBP)
	{
		returnVal = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}
	
	if ( ! pBP->init(payloadSize) )
	{
		returnVal = PTSSH_ERR_CouldNotCreateBinaryPacket;
		goto error;
	}
	
	//Set message type
	pBP->writeByte(SSH_MSG_NEWKEYS);


	/*******************
	Before we send our "encryption done" (SSH_MSG_NEWKEYS)message, 
	create our new cipher objects and give them to SS and SR so they
	are ready to switch ciphers.
	*******************/
	returnVal = m_pCrypto->getCipher( &pEncrypt, m_KN_mac_CtoS, true);
	if ( returnVal != PTSSH_SUCCESS)
		goto error;

	returnVal = m_pCrypto->getCipher( &pDecrypt, m_KN_mac_StoC, false);
	if ( returnVal != PTSSH_SUCCESS)
		goto error;

	if ( ! pEncrypt || ! pDecrypt)
	{
		returnVal = PTSSH_ERR_CouldNotAllocateMemory;
		goto error;
	}

#ifdef PTSSH_SHOW_CONNECTION_DETAILS
	//print out the agreed upon stuff
	PTLOG((LL_debug1, "[PTsock] ********************************************************\n"));
	PTLOG((LL_debug1, "[PTsock] Key exchange: %s\n", getAlgKeyX(m_KN_keyx) ));
	PTLOG((LL_debug1, "[PTsock] Host key type: %s\n", getAlgPublicKey(m_KN_hostKey) ));
	PTLOG((LL_debug1, "[PTsock] ********************************************************\n"));
	PTLOG((LL_debug1, "[PTsock] Encryption    client -> server: %s\n", getAlgEncryption(m_KN_encrypt_CtoS)));
	PTLOG((LL_debug1, "[PTsock] HMAC          client -> server: %s\n", getAlgHmac(m_KN_mac_CtoS) )); 
	PTLOG((LL_debug1, "[PTsock] Compression   client -> server: %s\n", getAlgCompression(m_KN_comp_CtoS) ));
	PTLOG((LL_debug1, "[PTsock] ********************************************************\n"));
	PTLOG((LL_debug1, "[PTsock] Encryption    server -> client: %s\n", getAlgEncryption(m_KN_encrypt_StoC)));
	PTLOG((LL_debug1, "[PTsock] HMAC          server -> client: %s\n", getAlgHmac(m_KN_mac_StoC) ));
	PTLOG((LL_debug1, "[PTsock] Compression   server -> client: %s\n", getAlgCompression(m_KN_comp_StoC) ));
	PTLOG((LL_debug1, "[PTsock] ********************************************************\n"));
#endif /* PTSSH_SHOW_CONNECTION_DETAILS */


	m_pSS->setCipher( pEncrypt);
	m_pSR->setCipher( pDecrypt);

	m_macSizeOut = pEncrypt->macLen;
	m_blockSizeOut = pEncrypt->blockSize;

	PTLOG((LL_debug2, "Created new cipher objects!\n"));

	/*******************
	 * Send off our SSH_MSG_NEWKEYS
	 *******************/
	returnVal = m_pChannelMgr->queueOutboundData( pBP);
	if ( returnVal != PTSSH_SUCCESS)
		goto error;

	PTLOG((LL_debug1, "Sent SSH_MSG_NEWKEYS\n"));
	pBP = NULL;

	return returnVal;

error:
	if ( *ppBP)
	{
		delete *ppBP;
		*ppBP = NULL;
	}

	if ( pBP)
		delete pBP;

	return returnVal;
}

///////////////////////////////////////////////////////////////////////////////
void
PTsshSocket::shutdown()
{
	if ( m_pSS)
	{
		if (m_pSS->isRunning())
			m_pSS->stopThread();

		delete m_pSS;
		m_pSS = NULL;
	}

	if ( m_pSR)
	{
		if (m_pSR->isRunning())
			m_pSR->stopThread();

		delete m_pSR;
		m_pSR = NULL;
	}

	//Close the socket if its open. We really don't care if this closes correctly or not
	close( m_sock);
}

///////////////////////////////////////////////////////////////////////////////
int32
PTsshSocket::getSessionID(uint8 **ppSessionID, uint32 &sessionLen)
{
	if ( m_pCrypto)
	{
		return m_pCrypto->getSessionID(ppSessionID, sessionLen);
	}

	return PTSSH_FAILURE;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTsshSocket::createSignature(
	uint8 *pSigData, uint32 sigDataLen,
	uint8 *pPublicKeyBlob, uint32 pPublicKeyBlobLen,
	uint8 *pPrivateKeyBlob, uint32 pPrivateKeyBlobLen,
	uint8 **ppSig, uint32 &sigLen)
{
	if ( m_pCrypto)
	{
		return m_pCrypto->createSignature(
			pSigData,
			sigDataLen,
			pPublicKeyBlob,
			pPublicKeyBlobLen,
			pPrivateKeyBlob,
			pPrivateKeyBlobLen,
			ppSig,
			sigLen);
	}

	return PTSSH_FAILURE;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTsshSocket::getServerHostKey( uint8**ppBuf, uint32 &bufLen, bool bAsMD5_hash)
{
	if ( m_pCrypto)
	{
		if ( bAsMD5_hash)
			return m_pCrypto->getServerHostKeyAsMD5(ppBuf, bufLen);
		else
			return m_pCrypto->getServerHostKeyAsSHA(ppBuf, bufLen);
	}

	return PTSSH_ERR_NullPointer;
}

///////////////////////////////////////////////////////////////////////////////
int32
PTsshSocket::rawSocketWrite(const char *pRAW, uint32 len)
{
	uint32
		totalSent = 0;
	
	int32
		result = 0;

	while (totalSent < len )
	{
		result = send( m_sock, (const char*)(pRAW + totalSent), len - totalSent, 0);

		if (result < 1)
			return result;	//return error
		else
			totalSent += result;
	}

	return PTSSH_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
bool
PTsshSocket::reallocate( char **ppC, uint32 size)
{
	if (*ppC)
		delete *ppC;
	*ppC = new char[size];
	if ( *ppC)
		return true;
	return false;
}

///////////////////////////////////////////////////////////////////////////////
KEYX_Type
PTsshSocket::setAlgKeyX(const char *pName)
{
	KEYX_Type type = KEYX_dh_unknown;
	
	/* KEYX_Type mappings */
	if (strcmp(pName, g_diffie_hellman_group1_sha1) == 0)
		type = KEYX_dh_group1_sha1;
	else if (strcmp(pName, g_diffie_hellman_group14_sha1) == 0)
		type = KEYX_dh_group14_sha1;

	return type;
}

///////////////////////////////////////////////////////////////////////////////
EncType
PTsshSocket::setAlgEncryption(const char *pName)
{
	EncType type = ENC_invalid;

	/* Encryption type mappings */
	if (strcmp(pName, g_3des_cbc) == 0)
		type = ENC_3des_cbc;
	else if (strcmp(pName, g_des_cbc) == 0)
		type = ENC_des_cbc;
	else if (strcmp(pName, g_blowfish_cbc) == 0)
		type = ENC_blowfish_cbc;
	else if (strcmp(pName, g_twofish256_cbc) == 0)
		type = ENC_twofish256_cbc;
	else if (strcmp(pName, g_twofish_cbc) == 0)
		type = ENC_twofish_cbc;
	else if (strcmp(pName, g_twofish192_cbc) == 0)
		type = ENC_twofish192_cbc;
	else if (strcmp(pName, g_twofish128_cbc) == 0)
		type = ENC_twofish128_cbc;
	else if (strcmp(pName, g_aes256_cbc) == 0)
		type = ENC_aes256_cbc;
	else if (strcmp(pName, g_aes192_cbc) == 0)
		type = ENC_aes192_cbc;
	else if (strcmp(pName, g_aes128_cbc) == 0)
		type = ENC_aes128_cbc;
	else if (strcmp(pName, g_serpent256_cbc) == 0)
		type = ENC_serpent256_cbc;
	else if (strcmp(pName, g_serpent192_cbc) == 0)
		type = ENC_serpent192_cbc;
	else if (strcmp(pName, g_serpent128_cbc) == 0)
		type = ENC_serpent128_cbc;
	else if (strcmp(pName, g_arcfour) == 0)
		type = ENC_arcfour;
	else if (strcmp(pName, g_idea_cbc) == 0)
		type = ENC_idea_cbc;
	else if (strcmp(pName, g_cast128_cbc) == 0)
		type = ENC_cast128_cbc;
#ifdef PTSSH_MultiThreaded_AES_CTR
	/* Multi-threaded AES support is enabled. IF the AES algorithm is running
	* in CTR mode (either single threaded or multi-threaded on the remote server)
	* default to using our multi-threaded AES-CTR stuff */
	else if (strcmp(pName, g_aes128_ctr) == 0)
		type = ENC_MT_aes128_ctr;
	else if (strcmp(pName, g_aes192_ctr) == 0)
		type = ENC_MT_aes192_ctr;
	else if (strcmp(pName, g_aes256_ctr) == 0)
		type = ENC_MT_aes256_ctr;
#else
	else if (strcmp(pName, g_aes128_ctr) == 0)
		type = ENC_aes128_ctr;
	else if (strcmp(pName, g_aes192_ctr) == 0)
		type = ENC_aes192_ctr;
	else if (strcmp(pName, g_aes256_ctr) == 0)
		type = ENC_aes256_ctr;
#endif

	else if (strcmp(pName, g_none) == 0)
		type = ENC_none;

	return type;
}

///////////////////////////////////////////////////////////////////////////////
MAC_Type
PTsshSocket::setAlgHmac(char *pName)
{
	MAC_Type type = MAC_invalid;

	/* MAC type mappings */
	if (strcmp(pName, g_hmac_sha1) == 0)
		type = MAC_hmac_sha1;
	else if (strcmp(pName, g_hmac_sha1_96) == 0)
		type = MAC_hmac_sha1_96;
	else if (strcmp(pName, g_hmac_md5) == 0)
		type = MAC_hmac_md5;
	else if (strcmp(pName, g_hmac_md5_96) == 0)
		type = MAC_hmac_md5_96;
	else if (strcmp(pName, g_none) == 0)
		type = MAC_none;

	return type;
}

///////////////////////////////////////////////////////////////////////////////
HOST_Type
PTsshSocket::setAlgPublicKey(char *pName)
{
	HOST_Type type = HOST_invalid;

	/* Host key mappings */
	if (strcmp(pName, g_ssh_rsa) == 0)
		type = HOST_rsa;
	else if (strcmp(pName, g_ssh_dss) == 0)
		type = HOST_dss;

	return type;
}

///////////////////////////////////////////////////////////////////////////////
COMP_Type
PTsshSocket::setAlgCompression(char *pName)
{
	COMP_Type type = COMP_invalid;

	/* Compression mappings */
	if (strcmp(pName, g_zlib) == 0)
		type = COMP_zlib;
	else if (strcmp(pName, g_zlibOpenssh) == 0)
		type = COMP_zlib_openssh;
	else if (strcmp(pName, g_none) == 0)
		type = COMP_none;	//Set to the invalid type

	return type;
}

#ifdef PTSSH_SHOW_CONNECTION_DETAILS
///////////////////////////////////////////////////////////////////////////////
const char *
PTsshSocket::getAlgKeyX(KEYX_Type type)
{
	if (type == KEYX_dh_group1_sha1) 
		return g_diffie_hellman_group1_sha1;
	else if (type == KEYX_dh_group14_sha1)
		return g_diffie_hellman_group14_sha1;

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
const char *
PTsshSocket::getAlgEncryption(EncType type)
{
	/* Encryption type mappings */
	if (type == ENC_3des_cbc)
		return g_3des_cbc;
	else if (type == ENC_des_cbc)
		return g_des_cbc;
	else if (type == ENC_blowfish_cbc)
		return g_blowfish_cbc;
	else if (type == ENC_twofish256_cbc)
		return g_twofish256_cbc;
	else if (type == ENC_twofish_cbc)
		return g_twofish_cbc;
	else if (type == ENC_twofish192_cbc)
		return g_twofish192_cbc;
	else if (type == ENC_twofish128_cbc)
		return g_twofish128_cbc;
	else if (type == ENC_aes256_cbc)
		return g_aes256_cbc;
	else if (type == ENC_aes192_cbc)
		return g_aes192_cbc;
	else if (type == ENC_aes128_cbc)
		return g_aes128_cbc;
	else if (type == ENC_serpent256_cbc)
		return g_serpent256_cbc;
	else if (type == ENC_serpent192_cbc)
		return g_serpent192_cbc;
	else if (type == ENC_serpent128_cbc)
		return g_serpent128_cbc;
	else if (type == ENC_arcfour)
		return g_arcfour;
	else if (type == ENC_idea_cbc)
		return g_idea_cbc;
	else if (type == ENC_cast128_cbc)
		return g_cast128_cbc;

#ifdef PTSSH_MultiThreaded_AES_CTR
	else if (type == ENC_MT_aes128_ctr)
		return g_mtAes128_ctr;
	else if (type == ENC_MT_aes192_ctr)
		return g_mtAes192_ctr;
	else if (type == ENC_MT_aes256_ctr)
		return g_mtAes256_ctr;
#endif

	else if (type == ENC_aes128_ctr)
		return g_aes128_ctr;
	else if (type == ENC_aes192_ctr)
		return g_aes192_ctr;
	else if (type == ENC_aes256_ctr)
		return g_aes256_ctr;
	else if (type == ENC_none)
		return g_none;

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
const char *
PTsshSocket::getAlgHmac(MAC_Type type)
{
	/* MAC type mappings */
	if (type == MAC_hmac_sha1)
		return g_hmac_sha1;
	else if (type == MAC_hmac_sha1_96)
		return g_hmac_sha1_96;
	else if (type == MAC_hmac_md5)
		return g_hmac_md5;
	else if (type == MAC_hmac_md5_96)
		return g_hmac_md5_96;
	else if (type == MAC_none)
		return g_none;

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
const char *
PTsshSocket::getAlgPublicKey(HOST_Type type)
{
	/* Host key mappings */
	if (type == HOST_rsa)
		return g_ssh_rsa;
	else if (type == HOST_dss)
		return g_ssh_dss;

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
const char *
PTsshSocket::getAlgCompression(COMP_Type type)
{
	/* Compression mappings */
	if (type == COMP_none)
		return g_none;
	else if (type == COMP_zlib_openssh)
		return g_zlibOpenssh;
	else if (type == COMP_zlib)
		return g_zlib;

	return NULL;
}

#endif /* #ifdef PTSSH_SHOW_CONNECTION_DETAILS */
