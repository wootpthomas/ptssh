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


#include <string.h>

#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif

#include "CryptoStuff.h"

#include "PTsshSocket.h"
#include "Utility.h"
#include "PTsshLog.h"




//

///////////////////////////////////////////////////////////////////////////////
//Known P-value as defined in RFC 2409, 128 bytes
static const unsigned char m_p_dh_group1_sha[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xBF, 0x2E, 0x80, 0x82, 0xCF, 0x1B, 0x9D, 0x81, 
	0x82, 0x2E, 0x86, 0xCE, 0xBC, 0x1C, 0xBD, 0xCE, 
    0x83, 0x26, 0x97, 0x9C, 0x8E, 0x3D, 0x8C, 0xC0, 
	0xCF, 0x00, 0x87, 0x87, 0x88, 0x26, 0x9B, 0x8F, 
    0x83, 0x23, 0x8C, 0xCE, 0x8C, 0x2E, 0x99, 0x82, 
	0x8A, 0x2B, 0xD5, 0xBE, 0x9C, 0x3C, 0x9D, 0xCF,
};

//Known P-value as defined in RFC 2409, 256 bytes
static const unsigned char m_p_dh_group14_sha[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
    0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
    0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
    0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
    0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
    0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xA3, 0x1A, 0xC6, 0x84, 0xD7, 0x1E, 0xC6, 0x95, 
	0x85, 0x13, 0xDD, 0x8E, 0xD7, 0x05, 0xCE, 0x84, 
    0xD7, 0x05, 0xDD, 0x9E, 0x83, 0x06, 0xCA, 0x99, 
	0xD7, 0x13, 0xC1, 0x93, 0xD7, 0x16, 0xCA, 0x84, 
    0x9E, 0x15, 0xC1, 0x92, 0x93, 0x52, 0xCD, 0x8E, 
	0xD7, 0x22, 0xCE, 0x82, 0x9B, 0x52, 0xFB, 0x9F, 
    0x98, 0x1F, 0xCE, 0x84, 0xD9, 0x52, 0xE6, 0xD7, 
	0x95, 0x17, 0xC8, 0x96, 0x99, 0x52, 0xCB, 0x92, 
    0x81, 0x17, 0xC3, 0x98, 0x87, 0x1B, 0xC1, 0x90, 
	0xD7, 0x1B, 0xDB, 0xD7, 0x98, 0x1C, 0x8F, 0xB9, 
    0x98, 0x04, 0x81, 0xD7, 0xC6, 0x44, 0x81, 0xD7, 
	0xC5, 0x42, 0x9F, 0xCF, 0xD7, 0x42, 0xF0, 0x98, 
};

///////////////////////////////////////////////////////////////////////////////
CryptoStuff::CryptoStuff(PTsshSocket * const pSshSocket):
m_bIsSessionIDSet(0),
pV_C(0),
pV_S(0),
pI_C(0),
pI_S(0),
pK_S(0),
pHash(0),
m_pSigOfH(0),
m_pPublicKey(0),
m_sizeH(0),
pK_mpint(0),
pf_mpint(0),
pe_mpint(0),
m_type( KEYX_dh_unknown),
m_pSshSocket(pSshSocket ),
p_rsaE(0),
p_rsaN(0),
p_dssP(0),
p_dssQ(0),
p_dssG(0),
p_dssY(0),
m_pDSA(0),
m_pRSA(0),
m_pRSAsig(0),
m_pDSAsig(0),
m_sizeRSAsig(0),
m_sizeDSAsig(0)
{
	memset(	m_sessionID, 0x0, SHA_DIGEST_LENGTH);
	memset( m_serverHostKeyMD5, 0x0, MD5_DIGEST_LENGTH);
	memset( m_serverHostKeySHA, 0x0, SHA_DIGEST_LENGTH);
	m_pBigNumContext = BN_CTX_new();

	//Initialize big numbers
	p_p = BN_new();
	p_g = BN_new();
	p_e = BN_new();
	p_x = BN_new();
	p_f = BN_new();
	p_k = BN_new();
}

///////////////////////////////////////////////////////////////////////////////
CryptoStuff::~CryptoStuff(void)
{
	if ( pV_C)		delete pV_C;
	if ( pV_S)		delete pV_S;
	if ( pI_C)		delete pI_C;
	if ( pI_S)		delete pI_S;
	if ( pK_S)		delete pK_S;
	if ( pK_mpint)	delete pK_mpint;
	if ( pf_mpint)	delete pf_mpint;
	if ( pe_mpint)	delete pe_mpint;
	if ( pHash)		delete pHash;
	if ( m_pSigOfH) delete [] m_pSigOfH;

	if ( p_p)	BN_clear_free(p_p);
	if ( p_g)	BN_clear_free(p_g);
	if ( p_e)	BN_clear_free(p_e);
	if ( p_x)	BN_clear_free(p_x);
	if ( p_f)	BN_clear_free(p_f);
	if ( p_k)	BN_clear_free(p_k);
		
	if (m_pBigNumContext)	BN_CTX_free(m_pBigNumContext);
}

///////////////////////////////////////////////////////////////////////////////
bool 
CryptoStuff::setKeyExchangeType(KEYX_Type type)
{
	switch (type){
		case KEYX_dh_group1_sha1: // = 1,
		case KEYX_dh_group14_sha1: // = 2
			m_type = type;
			return true;
			break;
		default:
			m_type = KEYX_dh_unknown;
	}
	return false;
}

///////////////////////////////////////////////////////////////////////////////
bool 
CryptoStuff::compute_E()
{
	//Generate x, set p
	switch( m_type){
		case KEYX_dh_group1_sha1:
			BN_rand(p_x, 128, 0, -1);
			BN_bin2bn(m_p_dh_group1_sha, 128, p_p);
			break;
		case KEYX_dh_group14_sha1:
			BN_rand(p_x, 256, 0, -1);
			BN_bin2bn(m_p_dh_group14_sha, 256, p_p);
			break;
		default:
			return false;
	}

	//Set g -> The generator is 2 (decimal)
	//as found in SSH RFC.... http://www.ietf.org/rfc/rfc2409.txt
	BN_set_word(p_g, 2);

	//Computes p_e = p_g^p_x mod p_p
	BN_mod_exp(p_e, p_g, p_x, p_p, m_pBigNumContext);

	return true;
}

///////////////////////////////////////////////////////////////////////////////
int
CryptoStuff::getE_byteCount()
{
	if ( ! p_e)
		return 0;

int bits = BN_num_bits(p_e);
	if ( BN_num_bits(p_e) % 8)
		return BN_num_bytes(p_e);

	return BN_num_bytes(p_e) + 1;
}

///////////////////////////////////////////////////////////////////////////////
void
CryptoStuff::setF_andComputeSharedSecret(unsigned char *pF, uint32 size)
{
	BN_bin2bn(pF, size, p_f);

	//Now compute the secret -> p_k = p_f^p_x, mod p_p
	BN_mod_exp(p_k, p_f, p_x, p_p, m_pBigNumContext);
}

///////////////////////////////////////////////////////////////////////////////
bool
CryptoStuff::setPublicKey(char *pBuf, uint32 bufLen)
{
	uint32
		len, eLen, nLen, pLen, qLen, gLen, yLen;
	if ( ! pBuf || bufLen == 0)
		return false;

	PTSSH_htons32( *((uint32*)pBuf), &len);
	pBuf += 4;
	// 4 + 7 + 4 + eLen + 4 + nLen;
	if ( len == 7 && strncmp( (char*)pBuf, "ssh-rsa", 7) == 0)
	{
		//Key type is ssh-rsa
		m_pRSA = RSA_new();
		if ( ! m_pRSA)
			return false;

		pBuf += len;
		PTSSH_htons32( *((uint32*)pBuf), &eLen);
		pBuf += 4;

		//Get BIGNUM_e
		m_pRSA->e = BN_new();
		BN_bin2bn( (const unsigned char*)pBuf, eLen, m_pRSA->e);

		pBuf += eLen;
		PTSSH_htons32( *((uint32*)pBuf), &nLen);
		pBuf += 4;

		//Get BIGNUM_n
		m_pRSA->n = BN_new();
		BN_bin2bn( (const unsigned char*)pBuf, nLen, m_pRSA->n);
		return true;
	}
	else if ( len == 7 && strncmp( (char*)pBuf, "ssh-dss", 7) == 0)
	{
		//Key type is ssh-dss
		m_pDSA = DSA_new();

		// p
		pBuf += len;
		PTSSH_htons32( *((uint32*)pBuf), &pLen);
		pBuf += 4;
		m_pDSA->p = BN_new();
		BN_bin2bn( (const unsigned char*)pBuf, pLen, m_pDSA->p);

		// q
		pBuf += pLen;
		PTSSH_htons32( *((uint32*)pBuf), &qLen);
		pBuf += 4;
		m_pDSA->q = BN_new();
		BN_bin2bn( (const unsigned char*)pBuf, qLen, m_pDSA->q);

		// g
		pBuf += qLen;
		PTSSH_htons32( *((uint32*)pBuf), &gLen);
		pBuf += 4;
		m_pDSA->g = BN_new();
		BN_bin2bn( (const unsigned char*)pBuf, gLen, m_pDSA->g);

		// y
		pBuf += gLen;
		PTSSH_htons32( *((uint32*)pBuf), &yLen);
		pBuf += 4;
		m_pDSA->pub_key = BN_new();
		BN_bin2bn( (const unsigned char*)pBuf, yLen, m_pDSA->pub_key);

		//We don't do anything with any "x" param...? should we?

		return true;
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
bool
CryptoStuff::setSignatureOfH(const char *pBuf, const uint32 bufLen)
{
	uint32
		keyNameLen = 0,
		sigLen = 0;

	if ( ! pBuf || bufLen == 0)
		return false;

	//Clear out the signature of H
	if ( m_pSigOfH)
	{
		delete m_pSigOfH;
		m_pSigOfH = NULL;
		m_pSigOfHLen = 0;
	}

	PTSSH_htons32( *((uint32*)pBuf), &keyNameLen);
	pBuf += 4;
	// 4 + 7 + 4 + eLen + 4 + nLen;
	if ( keyNameLen == 7 && strncmp( (char*)pBuf, "ssh-rsa", 7) == 0)
	{
		pBuf += keyNameLen;
		PTSSH_htons32( *((uint32*)pBuf), &sigLen);
		pBuf += 4;
	}
	else if ( keyNameLen == 7 && strncmp( (char*)pBuf, "ssh-dss", 7) == 0)
	{
		pBuf += keyNameLen;
		PTSSH_htons32( *((uint32*)pBuf), &sigLen);
		pBuf += 4;
	}

	if ( sigLen > 0)
	{
		m_pSigOfH = new unsigned char[sigLen];
		m_pSigOfHLen = sigLen;
		if ( m_pSigOfH){
			memcpy(m_pSigOfH, pBuf, sigLen);
			return true;
		}
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
void 
CryptoStuff::copyE_toBuf( char **ppBuf)
{
	if (*ppBuf)
	{
		if ( BN_num_bytes(p_e) % 8) //don't need leading 0x0 byte
		{
			memset(*ppBuf, 0x0, BN_num_bytes(p_e));
			BN_bn2bin(p_e, (unsigned char *) *ppBuf);
		}
		else //Need leading 0x0 byte
		{
			memset(*ppBuf, 0x0, BN_num_bytes(p_e)+1);
			BN_bn2bin(p_e, (unsigned char *) *ppBuf+1);
		}
	}
}


///////////////////////////////////////////////////////////////////////////////
bool
CryptoStuff::setV_C(const char *pClientID, uint32 size)
{	
	if ( m_pSshSocket)
		return makeSSHType_string( pClientID, size, &pV_C);
	else
		return false;
}

///////////////////////////////////////////////////////////////////////////////
bool
CryptoStuff::setV_S(const char *pServerID, uint32 size)
{	
	if ( m_pSshSocket)
		return makeSSHType_string( pServerID, size, &pV_S);
	else
		return false;
}

///////////////////////////////////////////////////////////////////////////////
bool
CryptoStuff::setI_C(char *pClientKex, uint32 size)
{	
	if ( pI_C)
		delete pI_C;

	pI_C = new unsigned char[size + 4];
	if ( pI_C)
	{
		PTSSH_htons32(size, (uint32*)pI_C);
		memcpy(pI_C + 4, pClientKex, size);
		return true;
	}
	
	return false;
}

///////////////////////////////////////////////////////////////////////////////
bool
CryptoStuff::setI_S(char *pServerKex, uint32 size)
{
	if ( pI_S)
		delete pI_S;

	pI_S = new unsigned char[size + 4];
	if ( pI_S)
	{
		PTSSH_htons32(size, (uint32*)pI_S);
		memcpy(pI_S + 4, pServerKex, size);
		return true;
	}
	
	return false;
}

///////////////////////////////////////////////////////////////////////////////
bool
CryptoStuff::setK_S(char *pServerHostKey, uint32 size)
{	
	if ( m_pSshSocket)
	{
		if ( pK_S)
			delete pK_S;

		pK_S = new unsigned char[size + 4];
		if ( pK_S)
		{
			PTSSH_htons32(size, (uint32*)pK_S);
			memcpy(pK_S + 4, pServerHostKey, size);
		}
		else
			return false;

		MD5_CTX md5Ctx;
		MD5_Init( &md5Ctx);
		MD5_Update( &md5Ctx, pK_S + 4, size);
		MD5_Final( m_serverHostKeyMD5, &md5Ctx);

		SHA_CTX shaCtx;
		SHA1_Init( &shaCtx);
		SHA1_Update( &shaCtx, pK_S + 4, size);
		SHA1_Final( m_serverHostKeySHA, &shaCtx);
		
		return true;
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
BIGNUM *
CryptoStuff::getE()
{
	if ( p_e)
		return p_e;
	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
bool
CryptoStuff::computeSessionID()
{
	//Make sure all needed items are at least valid
	bool bIsValid = 
		p_k && p_f && p_e && pV_C && pV_S && pI_C && pI_S && pK_S;
	if ( ! bIsValid)
		return false;

	if ( ! makeSSHType_mpint( p_e, &pe_mpint))
		return false;
	if ( ! makeSSHType_mpint( p_f, &pf_mpint))
		return false;
	if ( ! makeSSHType_mpint( p_k, &pK_mpint))
		return false;


	/* Create the exchange hash (H  -> m_H ), aka, sessionID -> if first time
	PT NOTE: These types are in SSH string and SSH mpint format!!!
	 The hash H is computed as the HASH hash of the concatenation of the following:
      string    V_C, the client's identification string (CR and LF excluded)
      string    V_S, the server's identification string (CR and LF excluded)
      string    I_C, the payload of the client's SSH_MSG_KEXINIT
      string    I_S, the payload of the server's SSH_MSG_KEXINIT
      string    K_S, the host key
      mpint     e, exchange value sent by the client
      mpint     f, exchange value sent by the server
      mpint     K, the shared secret */

	SHA_CTX exchangeShaCtx;
	SHA1_Init( &exchangeShaCtx);

	SHA1_Update(&exchangeShaCtx, pV_C, PTSSH_htons32( *((uint32*)pV_C) ) + 4);
	SHA1_Update(&exchangeShaCtx, pV_S, PTSSH_htons32( *((uint32*)pV_S) ) + 4);
	SHA1_Update(&exchangeShaCtx, pI_C, PTSSH_htons32( *((uint32*)pI_C) ) + 4);
	SHA1_Update(&exchangeShaCtx, pI_S, PTSSH_htons32( *((uint32*)pI_S) ) + 4);
	SHA1_Update(&exchangeShaCtx, pK_S, PTSSH_htons32( *((uint32*)pK_S) ) + 4);
	// diffie-hellman-group exchange hashes have additional stuff
		//TODO: implement additional stuff

	SHA1_Update(&exchangeShaCtx, pe_mpint, PTSSH_htons32( *((uint32*)pe_mpint) ) + 4);
	SHA1_Update(&exchangeShaCtx, pf_mpint, PTSSH_htons32( *((uint32*)pf_mpint) ) + 4 );
	SHA1_Update(&exchangeShaCtx, pK_mpint, PTSSH_htons32( *((uint32*)pK_mpint) ) + 4);

	//Set the sessionID (H -hash). When we do keyX for the first time, m_sessionID = m_H
	SHA1_Final( (unsigned char *)&m_H, &exchangeShaCtx);

	//If the sessionID hasn't been set yet, set it. This only happens during the very 1st keyx
	if ( ! m_bIsSessionIDSet)
	{
		memcpy( &m_sessionID, &m_H, SHA_DIGEST_LENGTH);
		m_bIsSessionIDSet = true;
	}

	return true;
}

///////////////////////////////////////////////////////////////////////////////
bool
CryptoStuff::verifySigOfH_onTheBigHash()
{
	unsigned char 
		hash[SHA_DIGEST_LENGTH];
	bool 
		bResult = false;

	SHA1( m_H, SHA_DIGEST_LENGTH, hash);

	if ( m_pRSA)
	{
		if ( RSA_verify(NID_sha1, hash, SHA_DIGEST_LENGTH, m_pSigOfH, m_pSigOfHLen, m_pRSA) == 1)
			bResult = true;
	}
	else if ( m_pDSA)
	{
		DSA_SIG
			DSA_Signature;

		//Some setup before we can verify
		DSA_Signature.r = BN_new();
		BN_bin2bn( m_pSigOfH, 20, DSA_Signature.r);
		DSA_Signature.s = BN_new();
		BN_bin2bn( m_pSigOfH + 20, 20, DSA_Signature.s);

		if ( DSA_do_verify(hash, SHA_DIGEST_LENGTH, &DSA_Signature, m_pDSA) == 1)
			bResult = true;

		BN_clear_free( DSA_Signature.r);
		BN_clear_free( DSA_Signature.s);
	}

	return bResult;
}

///////////////////////////////////////////////////////////////////////////////
bool
CryptoStuff::makeSSHType_mpint(const BIGNUM *pBN, unsigned char **ppBuf)
{
	uint32 bufSize;

	if (*ppBuf)
	{
		delete *ppBuf;
		*ppBuf = NULL;
	}

	if ( ! pBN)
		return false;
		
	//bufSize = (4) uint32 size + (1) leading zero byte *if needed* + BN_num_bytes()
	if ( BN_num_bits(pBN) % 8)	//don't need leading 0x0 byte
		bufSize = BN_num_bytes(pBN) + 4;
	else
		bufSize = BN_num_bytes(pBN) + 5;  //evenly divisible by 8, we need a leading 0x0 byte

	if ( *ppBuf)
		delete *ppBuf;

	*ppBuf = new unsigned char[bufSize];
	if ( ! *ppBuf)
		return false;

	//Put into mpint form as specified in RFC 4253
	//Set the size
	PTSSH_htons32(bufSize-4, (uint32*)*ppBuf);
	if ( BN_num_bits(pBN) % 8)
		BN_bn2bin(pBN, (*ppBuf)+4);
	else
	{
		(*ppBuf)[4] = 0;
		BN_bn2bin(pBN, (*ppBuf)+5);
	}

	return true;
}

///////////////////////////////////////////////////////////////////////////////
int32
CryptoStuff::getCipher(struct Cipher **ppCrypt, MAC_Type macType, bool bIsClientToServer)
{
	int32 result = PTSSH_SUCCESS;

	unsigned char 
		*p_iv = NULL,
		*p_key = NULL;
	
	//Clean out any previous ciphers
	if ( *ppCrypt)
	{
		delete *ppCrypt;
		*ppCrypt = NULL;
	}

	*ppCrypt = new struct Cipher();
	if ( *ppCrypt) 
	{
		//Initialize a cipher contexts
		EVP_CIPHER_CTX_init( &(*ppCrypt)->ctx);

		if ( bIsClientToServer)
			//Gets details about the cipher we want to use
			getCipherInfo( m_pSshSocket->getCrypt_CtoS(), *ppCrypt);
		else
			//Gets details about the cipher we want to use
			getCipherInfo( m_pSshSocket->getCrypt_StoC(), *ppCrypt);

		p_iv = new unsigned char[(*ppCrypt)->IV_len];
		p_key = new unsigned char[(*ppCrypt)->keyLen];
		if (p_iv && p_key)
		{
			/* Setup the IV 
			o  Initial IV client to server: HASH(K || H || "A" || session_id)
			(Here K is encoded as mpint and "A" as byte and session_id as raw
			data.  "A" means the single character A, ASCII 65).
			o  Initial IV server to client: HASH(K || H || "B" || session_id) */
			makeKeyHash(
				bIsClientToServer? 'A' : 'B',
				(*ppCrypt)->IV_len, p_iv);

			/* Setup the encryption key
			o  Encryption key client to server: HASH(K || H || "C" || session_id)
			o  Encryption key server to client: HASH(K || H || "D" || session_id) */
			makeKeyHash(
				bIsClientToServer? 'C' : 'D',
				(*ppCrypt)->keyLen, p_key);

			//Set the cipher function
			if ( bIsClientToServer)
				EVP_EncryptInit( &(*ppCrypt)->ctx, (*ppCrypt)->pEncAlg, p_key, p_iv );
			else
				EVP_DecryptInit( &(*ppCrypt)->ctx, (*ppCrypt)->pEncAlg, p_key, p_iv );
			
			//These are no longer needed now that the cipher is ready
			delete p_key;
			delete p_iv;

			//set MAC params
			(*ppCrypt)->macType = macType;
			switch( macType){
				case MAC_none:
					(*ppCrypt)->macLen = 0;
					break;
				case MAC_hmac_sha1:
				case MAC_hmac_md5:
					(*ppCrypt)->macLen = 20;
					break;
				case MAC_hmac_sha1_96:
				case MAC_hmac_md5_96:
					(*ppCrypt)->macLen = 12;
					break;
			}
			
			/* Setup the integrity Key for checking/signing packet integrity
			o  Integrity key client to server: HASH(K || H || "E" || session_id)
			o  Integrity key server to client: HASH(K || H || "F" || session_id) */
			makeKeyHash(
				bIsClientToServer? 'E' : 'F',
				(*ppCrypt)->macKeyLen,
				(*ppCrypt)->macKey);

			/* If compression is enabled, get compression objects for
			 * client to server and also for server to client
			 */
			if ( m_pSshSocket->isCompressionEnabled(bIsClientToServer))
			{
#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
				result = m_pSshSocket->getCompressionObj(bIsClientToServer, &(*ppCrypt)->pCompress );
				if (bIsClientToServer)
					(*ppCrypt)->m_compType = m_pSshSocket->getCompression_CtoS();
				else
					(*ppCrypt)->m_compType = m_pSshSocket->getCompression_StoC();
#endif
			}
		}
		else
			result = PTSSH_ERR_CouldNotAllocateMemory;
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	if (result != PTSSH_SUCCESS)
	{
		if ( *ppCrypt)
		{
			delete *ppCrypt;
			*ppCrypt = NULL;
		}
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32 
CryptoStuff::getSessionID(uint8 **ppSessionID, uint32 &sessionLen)
{
	if ( m_bIsSessionIDSet)
	{
		*ppSessionID = new uint8[SHA_DIGEST_LENGTH];
		if ( *ppSessionID)
		{
			memcpy(*ppSessionID, m_sessionID, SHA_DIGEST_LENGTH);
			sessionLen = SHA_DIGEST_LENGTH;
			return PTSSH_SUCCESS;
		}
		else
			return PTSSH_ERR_CouldNotAllocateMemory;
	}

	return PTSSH_ERR_SessionIDNotSet;
}

///////////////////////////////////////////////////////////////////////////////
int32 
CryptoStuff::createSignature(
	uint8 *pSigData, uint32 sigDataLen,
	uint8 *pPublicKeyBlob, uint32 pPublicKeyBlobLen,
	uint8 *pPrivateKeyBlob, uint32 pPrivateKeyBlobLen,
	uint8 **ppSig, uint32 &sigLen)
{
	int32
		result = PTSSH_ERR_UnknownKeyType;
	uint32
		algNameLen = PTSSH_htons32( (uint32*)pPublicKeyBlob );
	
	//Take a peek and see what type of key we need to sign
	if ( memcmp(pPublicKeyBlob + 4, "ssh-rsa", 7) == 0)
	{
		RSA *pRSA = NULL;

		//Extract the stuff from public and private keys
		result = rsaCreate(pPublicKeyBlob, pPublicKeyBlobLen, pPrivateKeyBlob, pPrivateKeyBlobLen, &pRSA);
		if ( result != PTSSH_SUCCESS)
			return result;

		//Verify that the private/public key pair is a match to one another
		result = rsaVerify( pRSA);
		if ( result != PTSSH_SUCCESS)
			return result;

		//Now sign the data
		result = rsaSign(pRSA, pSigData, sigDataLen, ppSig, sigLen);
	}
	else if ( memcmp(pPublicKeyBlob + 4, "ssh-dss", 7) == 0)
	{
		DSA *pDSA = NULL;

		//Extract the stuff from public and private keys
		result = dsaCreate(pPublicKeyBlob, pPublicKeyBlobLen, pPrivateKeyBlob, pPrivateKeyBlobLen, &pDSA);
		if ( result != PTSSH_SUCCESS)
			return result;

		//Verify that the private/public key pair is a match to one another
		result = dsaVerify( pDSA);
		if ( result != PTSSH_SUCCESS)
			return result;

		//Now sign the data
		result = dsaSign(pDSA, pSigData, sigDataLen, ppSig, sigLen);
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
CryptoStuff::getServerHostKeyAsMD5( uint8**ppBuf, uint32 &bufLen)
{
	if ( m_bIsSessionIDSet)
	{
		*ppBuf = new uint8[MD5_DIGEST_LENGTH];
		if ( ! *ppBuf)
			return PTSSH_ERR_CouldNotAllocateMemory;
		memcpy( *ppBuf, m_serverHostKeyMD5, MD5_DIGEST_LENGTH);
		bufLen = MD5_DIGEST_LENGTH;

		return PTSSH_SUCCESS;
	}

	return PTSSH_ERR_ServerHostKeyIsNotYetSet;
}

///////////////////////////////////////////////////////////////////////////////
int32
CryptoStuff::getServerHostKeyAsSHA( uint8**ppBuf, uint32 &bufLen)
{
	if ( m_bIsSessionIDSet)
	{
		*ppBuf = new uint8[SHA_DIGEST_LENGTH];
		if ( ! *ppBuf)
			return PTSSH_ERR_CouldNotAllocateMemory;
		memcpy( *ppBuf, m_serverHostKeySHA, SHA_DIGEST_LENGTH);
		bufLen = SHA_DIGEST_LENGTH;

		return PTSSH_SUCCESS;
	}

	return PTSSH_ERR_ServerHostKeyIsNotYetSet;
}

///////////////////////////////////////////////////////////////////////////////
//TODO: Add in proper bounds checking in case we get fed a malformed key!
//
//struct
//       {
//       BIGNUM *n;              // public modulus    <- filled from Public key
//       BIGNUM *e;              // public exponent   <- filled from Public key
//       BIGNUM *d;              // private exponent  <- filled from Private key
//       BIGNUM *p;              // secret prime factor <- filled from Private key
//       BIGNUM *q;              // secret prime factor <- filled from Private key
//       BIGNUM *dmp1;           // d mod (p-1)
//       BIGNUM *dmq1;           // d mod (q-1)
//       BIGNUM *iqmp;           // q^-1 mod p        <- filled from Private key
//       // ...
//       };
//RSA
int32
CryptoStuff::rsaCreate(
	uint8 *pPublicKeyBlob,
	uint32 pPublicKeyBlobLen,
	uint8 *pPrivateKeyBlob,
	uint32 pPrivateKeyBlobLen,
	RSA **ppRSA)
{
	uint8
		*pIter = pPublicKeyBlob + 4 + 7;
	uint32
		len = PTSSH_htons32( (uint32*)pIter );

	*ppRSA = RSA_new();
	if ( ! (*ppRSA))
		return PTSSH_ERR_CouldNotAllocateMemory;

	//Get BIGNUM_e the exponent, e
	pIter += 4;
	(*ppRSA)->e = BN_new();
	BN_bin2bn( (const unsigned char*)pIter, len, (*ppRSA)->e);

	pIter += len;
	len = PTSSH_htons32( (uint32*)pIter );
	pIter += 4;

	//Get BIGNUM_n the modulus, n
	(*ppRSA)->n = BN_new();
	BN_bin2bn( (const unsigned char*)pIter, len, (*ppRSA)->n);

	//Extract the rest of the data from the private key
	pIter = pPrivateKeyBlob;
	len = PTSSH_htons32( (uint32*)pIter );
	pIter += 4;

	//Fill in the private exponent, d
	(*ppRSA)->d = BN_new();
	BN_bin2bn( (const unsigned char*)pIter, len, (*ppRSA)->d);
	pIter += len;

	len = PTSSH_htons32( (uint32*)pIter );
	pIter += 4;

	//Fill in the secret prime factor, p
	(*ppRSA)->p = BN_new();
	BN_bin2bn( (const unsigned char*)pIter, len, (*ppRSA)->p);
	pIter += len;

	len = PTSSH_htons32( (uint32*)pIter );
	pIter += 4;

	//Fill in the secret prime factor, q
	(*ppRSA)->q = BN_new();
	BN_bin2bn( (const unsigned char*)pIter, len, (*ppRSA)->q);
	pIter += len;

	len = PTSSH_htons32( (uint32*)pIter );
	pIter += 4;

	//Fill in q^-1 mod p, aka: iqmp
	(*ppRSA)->iqmp = BN_new();
	BN_bin2bn( (const unsigned char*)pIter, len, (*ppRSA)->iqmp);

	return PTSSH_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
int32
CryptoStuff::rsaVerify(RSA *pRsaKey)
{
	BIGNUM n;
	int result;
	
	//Verify that n == p * q
	BN_mul( &n, pRsaKey->p, pRsaKey->q, m_pBigNumContext);
	result = BN_cmp( &n, pRsaKey->n);
	if ( result != 0)
		return PTSSH_ERR_BadRsaKey_N_NotEqual_P_times_Q;

	//Verify that p > q
	result = BN_cmp( pRsaKey->p, pRsaKey->q);
	if ( result <= 0)
		return PTSSH_ERR_BadRsaKey_P_lessThan_Q;

	//Verify that iqmp * q is equal to 1 mod p
	BN_mod_mul( &n, pRsaKey->iqmp, pRsaKey->q, pRsaKey->p, m_pBigNumContext);
	result = BN_is_one( &n);
	if ( result != 1)
		return PTSSH_ERR_BadRsaKey_iqmp_failed;

	//Verify that e * d is equal to 1, mod (p-1) and mod (q-1)
   //????

	return PTSSH_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
int32
CryptoStuff::rsaSign(RSA *pRsaKey, uint8 *pSigData, uint32 sigDataLen, uint8 **ppSig, uint32 &sigLen)
{
	SHA_CTX ctx;
	unsigned char hash[SHA_DIGEST_LENGTH];

	SHA1_Init( &ctx);

	//Hash the SessionID field as if its a SSH String
	PTSSH_htons32( SHA_DIGEST_LENGTH, (uint32*)hash);
	SHA1_Update( &ctx, hash, 4);
	SHA1_Update( &ctx, m_sessionID, SHA_DIGEST_LENGTH);

	//Hash the rest of the data
	SHA1_Update( &ctx, pSigData, sigDataLen);

	//Finalize the hash
	SHA1_Final( hash, &ctx);

	sigLen = RSA_size( pRsaKey);
	*ppSig = new uint8[sigLen];
	if ( ! *ppSig)
		return PTSSH_ERR_CouldNotAllocateMemory;

	if ( RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, *ppSig, &sigLen, pRsaKey) != 1)
		return PTSSH_ERR_RsaSigningFailure;

	return PTSSH_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
//TODO: Add in proper bounds checking in case we get fed a malformed key!
//
//struct
//       {
//       BIGNUM *p;              // prime number (public)
//       BIGNUM *q;              // 160-bit subprime, q | p-1 (public)
//       BIGNUM *g;              // generator of subgroup (public)
//       BIGNUM *priv_key;       // private key x
//       BIGNUM *pub_key;        // public key y = g^x
//       // ...
//       }
//DSA;
//
int32
CryptoStuff::dsaCreate(
		uint8 *pPublicKeyBlob,
		uint32 pPublicKeyBlobLen,
		uint8 *pPrivateKeyBlob,
		uint32 pPrivateKeyBlobLen,
		DSA **ppDSA)
{
	uint8
		*pIter = pPublicKeyBlob + 4 + 7;
	uint32
		len = PTSSH_htons32( (uint32*)pIter );

	*ppDSA = DSA_new();
	if ( ! (*ppDSA))
		return PTSSH_ERR_CouldNotAllocateMemory;

	//Get p
	pIter += 4;
	(*ppDSA)->p = BN_new();
	BN_bin2bn( (const unsigned char*)pIter, len, (*ppDSA)->p);

	pIter += len;
	len = PTSSH_htons32( (uint32*)pIter );
	pIter += 4;

	//Get q
	(*ppDSA)->q = BN_new();
	BN_bin2bn( (const unsigned char*)pIter, len, (*ppDSA)->q);

	pIter += len;
	len = PTSSH_htons32( (uint32*)pIter );
	pIter += 4;

	//Get g
	(*ppDSA)->g = BN_new();
	BN_bin2bn( (const unsigned char*)pIter, len, (*ppDSA)->g);

	pIter += len;
	len = PTSSH_htons32( (uint32*)pIter );
	pIter += 4;

	//Get pub_key
	(*ppDSA)->pub_key = BN_new();
	BN_bin2bn( (const unsigned char*)pIter, len, (*ppDSA)->pub_key);

	//Extract the rest of the data from the private key
	pIter = pPrivateKeyBlob;
	len = PTSSH_htons32( (uint32*)pIter );
	pIter += 4;

	//priv_key
	(*ppDSA)->priv_key = BN_new();
	BN_bin2bn( (const unsigned char*)pIter, len, (*ppDSA)->priv_key);

	return PTSSH_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
int32
CryptoStuff::dsaVerify(DSA *pDSA)
{
	//TODO: Check hash in DSS key
	//DSA_SIG dsaSig;

 //   dsaSig.r = BN_new();
	//dsaSig.s = BN_new();

 //   BN_bin2bn(sig, 20, dsasig.r);
 //   
 //   BN_bin2bn(sig + 20, 20, dsaSig.s);

 //   sha1(m, m_len, hash);
 //   ret = DSA_do_verify(hash, SHA_DIGEST_LENGTH, &dsaSig, dsactx);


	//TODO: Verify that g^x mod p == y
//	BIGNUM yCalc;
	//yCalc = BN_mod_pow ??? wtf


	return PTSSH_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
int32
CryptoStuff::dsaSign(DSA *pDsaKey, uint8 *pSigData, uint32 sigDataLen, uint8 **ppSig, uint32 &sigLen)
{



	return PTSSH_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
void 
CryptoStuff::makeKeyHash(const char type, uint32 neededLen, unsigned char* pHashResult)
{
	SHA_CTX ctx;
	uint32 currentLen = 0;

	unsigned char tmpBuf[SHA_DIGEST_LENGTH];
	while (currentLen < neededLen)
	{
		SHA1_Init( &ctx);
		SHA1_Update( &ctx, pK_mpint, PTSSH_htons32( *((uint32*)pK_mpint) ) + 4);
		SHA1_Update( &ctx, &m_H, SHA_DIGEST_LENGTH);

		if (currentLen == 0) //First time through
		{
			SHA1_Update( &ctx, &type, 1);
			SHA1_Update( &ctx, &m_sessionID, SHA_DIGEST_LENGTH);
		}
		else
		{
			/* The key or IV needed is bigger than the SHA_DIGEST_LENGTH. In this
			 * case, we keep feeding in the previous part we extracted to help us
			 * make a longer result */
			SHA1_Update( &ctx, pHashResult, currentLen);
		}
		
		//Get the hash result
		SHA1_Final( tmpBuf, &ctx);
		
		//Copy in however much we need
		int copyLen = neededLen - currentLen;
		if ( copyLen > SHA_DIGEST_LENGTH)
			copyLen = SHA_DIGEST_LENGTH;

		memcpy(pHashResult + currentLen, tmpBuf, copyLen);
		currentLen += copyLen;
	}
}

///////////////////////////////////////////////////////////////////////////////
void
CryptoStuff::getCipherInfo(EncType cipherType, struct Cipher *pCipher)
{
	//Initialize the cipher engines
	switch( cipherType){
		case ENC_aes128_cbc:
			pCipher->blockSize = 16;
			pCipher->IV_len = 16;
			pCipher->keyLen = 16;
			pCipher->pEncAlg =  (EVP_CIPHER*)EVP_aes_128_cbc();
			break;
		//case ENC_aes128_ctr:
		//	pCipher->blockSize = 16;
		//	pCipher->IV_len = 16;
		//	pCipher->keyLen = 16;
		//	pCipher->pEncAlg =  (EVP_CIPHER*)EVP_aes_128_ctr();
		//	break;
		case ENC_aes192_cbc:
			pCipher->blockSize = 16;
			pCipher->IV_len = 16;
			pCipher->keyLen = 24;
			pCipher->pEncAlg = (EVP_CIPHER*)EVP_aes_192_cbc();
			break;
		//case ENC_aes192_ctr:
		//	pCipher->blockSize = 16;
		//	pCipher->IV_len = 16;
		//	pCipher->keyLen = 24;
		//	pCipher->pEncAlg = (EVP_CIPHER*)EVP_aes_192_ctr();
		//	break;
		case ENC_aes256_cbc:
			pCipher->blockSize = 16;
			pCipher->IV_len = 16;
			pCipher->keyLen = 32;
			pCipher->pEncAlg = (EVP_CIPHER*)EVP_aes_256_cbc();
			break;
		//case ENC_aes256_ctr:
		//	pCipher->blockSize = 16;
		//	pCipher->IV_len = 16;
		//	pCipher->keyLen = 32;
		//	pCipher->pEncAlg = (EVP_CIPHER*)EVP_aes_256_ctr();
		//	break;
		case ENC_blowfish_cbc:
			pCipher->blockSize = 8;
			pCipher->IV_len = 8;
			pCipher->keyLen = 16;
			pCipher->pEncAlg = (EVP_CIPHER*)EVP_bf_cbc();
			break;
		case ENC_arcfour:
			pCipher->blockSize = 8;
			pCipher->IV_len = 8;
			pCipher->keyLen = 16;
			pCipher->pEncAlg = (EVP_CIPHER*)EVP_rc4();
			break;
		case ENC_cast128_cbc:
			pCipher->blockSize = 8;
			pCipher->IV_len = 8;
			pCipher->keyLen = 16;
			pCipher->pEncAlg = (EVP_CIPHER*)EVP_cast5_cbc();
			break;
		case ENC_3des_cbc:
			pCipher->blockSize = 8;
			pCipher->IV_len = 8;
			pCipher->keyLen = 24;
			pCipher->pEncAlg = (EVP_CIPHER*)EVP_des_ede3_cbc();
			break;

		/* Not yet implemented encryptions */
		case ENC_des_cbc:
		case ENC_twofish256_cbc:
		case ENC_twofish_cbc:
		case ENC_twofish192_cbc:
		case ENC_twofish128_cbc:
		case ENC_serpent256_cbc:
		case ENC_serpent192_cbc:
		case ENC_serpent128_cbc:
		case ENC_idea_cbc:
		case ENC_none:
		default:
			PTLOG((LL_error, "Encryption specified is not yet supported in PTssh!\n"));
			pCipher->blockSize = 0;
			pCipher->IV_len = 0;
			pCipher->keyLen = 0;
			pCipher->pEncAlg = NULL;
	}
}
