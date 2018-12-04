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

#ifndef _CRYPTOSTUFF_H
#define _CRYPTOSTUFF_H


/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"
//#include "Utility.h"

#include <openssl/opensslconf.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>

/*************************
 * Forward Declarations
 ************************/
class PTsshSocket;
class Compress;

/**
* This class helps out with everything crypto related...
*/
class CryptoStuff
{
public:

	/**
	* Define Cipher struct for public use. This object contains all info needed
	* for encryption/decryption, compression, MAC stuff and a few other related
	* items.
	*/
	struct Cipher{
		//Create a cipher context
		EVP_CIPHER_CTX
			ctx;

		//Pointer to the encryption object to use for encrypt/decrypt
		EVP_CIPHER
			*pEncAlg;
		
		MAC_Type
			macType;	/**< Specifies the MAC algorithm to use for checking/signing the
						integrity of packets */

#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
		Compress
			*pCompress; /**< Pointer to our compression object. IF compression is
						enabled, then this will point to the compression class to
						use to inflate/deflate packets */
#endif

		COMP_Type
			m_compType; /**< Publicly available compression type. This helps our SocketReceive
						object know when to enable packet compression based upon the compression
						scheme being used. */

		uint8
			blockSize,	/**< Length of the blocksize */
			macLen,		/**< Length of the Message authentication hash */
			macKeyLen,	/**< Length of the integrity key to use when calculating the
						MAC on packets */

						/**< Pointer to the MAC key used in packet integrity stuff */
			macKey[SHA_DIGEST_LENGTH],
			IV_len,		/**< Length of the initilization vector */
			keyLen;		/**< Length of the key */

		Cipher(){
			pEncAlg = NULL;
#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
			pCompress = NULL;
#endif
			m_compType = COMP_none;
			blockSize = 8;
			macType = MAC_none;
			macLen = 0;
			macKeyLen = SHA_DIGEST_LENGTH;
			IV_len = 0;
			keyLen = 0;
		}
	};


	CryptoStuff( PTsshSocket * const pSshSocket);
	~CryptoStuff(void);

	/** This sets up the hashing algorithm type. This should be called
	* first before any other function!
	*/
	bool setKeyExchangeType(KEYX_Type type);

	/**
	* Generates a random number X (1 < x < q) and computes
	* e = g^x mod p. 
	@return Returns the number of bytes that e takes up or returns
		0 on failure
	*/
	bool compute_E();

	/**
	* Gets e, the exchange value for the client
	@return Returns e
	*/
	BIGNUM * getE();

	/**
	* Returns the number of bytes that make up "e"
	*/
	int getE_byteCount();

	/**
	* Set 'f', the exchange value sent by the server. This will also then compute
	* the shared secret "K".
	@param pF Pointer to a buffer holding the binary representation
		of a BIGNUM
	@param size The length of the passed in buffer.
	*/
	void setF_andComputeSharedSecret(unsigned char *pF, uint32 size);

	/**
	* This is the certificate or public key that the server sent us. We will
	* take in a buffer, figure out which was given and deal with the data as
	* needed.
	@param pBuf Pointer to the buffer holding data to be examined
	@param buflen Length of the given buffer
	*/
	bool setPublicKey(char *pBuf, uint32 buflen);

	/**
	* Set 'H'. This class takes ownership of the pointer!
	*The hash H is computed as the HASH hash of the concatenation of the
	*following:

      string    V_C, the client's identification string (CR and LF
                excluded)
      string    V_S, the server's identification string (CR and LF
                excluded)
      string    I_C, the payload of the client's SSH_MSG_KEXINIT
      string    I_S, the payload of the server's SSH_MSG_KEXINIT
      string    K_S, the host key
      mpint     e, exchange value sent by the client
      mpint     f, exchange value sent by the server
      mpint     K, the shared secret

	@param pF Pointer to a buffer holding the binary representation
		of a BIGNUM
	@param size The length of the passed in buffer.
	@return Returns true if the signature was successfully parsed and set
	*/
	bool setSignatureOfH(const char *pHsig, const uint32 size);

	/**
	* Copies the bytes of 'e' into the specified buffer. Make sure the
	* passed in buffer has enough space!
	*/
	void copyE_toBuf( char **ppBuf);

	/**
	* Sets the clients identification string (CR and LF excluded). The value
	* is copied from the given pointer.
	*/
	bool setV_C( const char *pClientID, uint32 size);

	/**
	* Sets the servers identification string (CR and LF excluded). The value
	* is copied from the given pointer.
	*/
	bool setV_S( const char *pServerID, uint32 size);

	/**
	* Sets the clients SSH_MSG_KEXINIT payload, I_C. I_C is in SSH mpint format.
	* The value is copied from the given pointer.
	*/
	bool setI_C( char *pClientKex, uint32 size);

	/**
	* Sets the servers SSH_MSG_KEXINIT payload, I_S. I_S is in SSH mpint format.
	* The value is copied from the given pointer
	*/
	bool setI_S( char *pServerKex, uint32 size);

	/**
	* Sets the server's host key. The value
	* is copied from the given pointer.
	*/
	bool setK_S( char *pServerHostKey, uint32 size);
	
	/**
	* After everything has been set, you call this function to do some final
	* calculations. After it returns true, you can then get things like
	* the sessionID and the IV and Key to use for encryption
	*/
	bool computeSessionID();

	/**
	* This will take the signature of H and try to verify it against the big Hash, 
	* thats the hash of hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
	* If it verifies, then we are good to go! If it fails, something's wrong or
	* perhaps we are being h@x0r3d! */
	bool verifySigOfH_onTheBigHash();

	/**
	* Gets the encryption/decryption objects. We use this to encrypt/decrypt any data before
	* we send/recieve it to/from the socket. */
	int32 getCipher(struct Cipher **ppCrypt, MAC_Type macType, bool bIsClientToServer);

	/**
	* Gets the session ID
	*/
	int32 getSessionID(uint8 **ppSessionID, uint32 &sessionLen);

	/**
	* Creates a signature over the given data.
	*/
	int32 createSignature(
		uint8 *pSigData,
		uint32 sigDataLen,
		uint8 *pPublicKeyBlob, uint32 pPublicKeyBlobLen,
		uint8 *pPrivateKeyBlob, uint32 pPrivateKeyBlobLen,
		uint8 **ppSig,
		uint32 &sigLen);

	/**
	* Makes a copy of the server's host key in the format of an MD5 hash
	*/
	int32 getServerHostKeyAsMD5( uint8**ppBuf, uint32 &bufLen);

	/**
	* Makes a copy of the server's host key in the format of an SHA-1 hash
	*/
	int32 getServerHostKeyAsSHA( uint8**ppBuf, uint32 &bufLen);

	/**
	* Given a BIGNUM pointer, this will allocate and return a buffer and its
	* size of the BIGNUM in SSH mpint format 
	*/
	static bool makeSSHType_mpint(const BIGNUM *pBN, unsigned char **ppBuf);

private:

	/**
	* This is used to create the IVs, encryption Keys, integrity Keys for all data going
	* client -> server and server -> client. It uses the secret(K), the main hash (H), 
	* the sessionID(m_sessionID) and a character that specifies which hash we are
	* creating. The result is a hash that is placed in the buffer pHashResult.
	From SSH RFC 4253:
		Encryption keys MUST be computed as HASH, of a known value and K, as
		follows:
		o  Initial IV client to server: HASH(K || H || "A" || session_id)
		  (Here K is encoded as mpint and "A" as byte and session_id as raw
		  data.  "A" means the single character A, ASCII 65).
		o  Initial IV server to client: HASH(K || H || "B" || session_id)
		o  Encryption key client to server: HASH(K || H || "C" || session_id)
		o  Encryption key server to client: HASH(K || H || "D" || session_id)
		o  Integrity key client to server: HASH(K || H || "E" || session_id)
		o  Integrity key server to client: HASH(K || H || "F" || session_id)

	@param[in] type A character specifying what IV or encryption/integrity key we are building
	@param[in] neededLen The length of the hash
	@param[out] pHashResult A pointer to a buffer large enough to hold the requested hash
	*/
	void makeKeyHash(const char type, uint32 neededLen, unsigned char* pHashResult);

	/**
	* This returns info about the type of encryption
	@param[in] cipherType Specifies the type of cipher we are interested in
	@param[out] blockSize Blocksize in bytes of the specified cipher
	@param[out] IV_len IV length in bytes of the specified cipher
	@param[out] keyLen Key length in bytes of the specified cipher
	@param[out] ppCipher Pointer to a pointer. Points to the encryption cipher function to use
		when calling the cipher's initialize function. Cast this to whatever type is needed.
	*/
	void getCipherInfo(EncType cipherType, struct Cipher *pCipher);

	/**
	* Extracts the RSA stuff from a public and private key. This gives us a RSA
	* object that can be used to sign data with and create a signature.
	*/
	int32 rsaCreate(
		uint8 *pPublicKeyBlob,
		uint32 pPublicKeyBlobLen,
		uint8 *pPrivateKeyBlob,
		uint32 pPrivateKeyBlobLen,
		RSA **ppRSA);

	/**
	* Verifies that all the components in the specified RSA key are valid
	*/
	int32 rsaVerify(RSA *pRSA);

	/**
	* Given a RSA item and a chunck of data, it signs it
	*/
	int32 rsaSign(RSA *pRsaKey, uint8 *pSigData, uint32 sigDataLen, uint8 **ppSig, uint32 &sigLen);

	/**
	* Extracts the DSA stuff from a public and private key. This gives us a DSA
	* object that can be used to sign data with and create a signature.
	*/
	int32 dsaCreate(
		uint8 *pPublicKeyBlob,
		uint32 pPublicKeyBlobLen,
		uint8 *pPrivateKeyBlob,
		uint32 pPrivateKeyBlobLen,
		DSA **ppDSA);

	/**
	* Verifies that all the components in the specified DSA key are valid
	*/
	int32 dsaVerify(DSA *pDSA);

	/**
	* Given a DSA item and a chunck of data, it signs it
	*/
	int32 dsaSign(DSA *pDsaKey, uint8 *pSigData, uint32 sigDataLen, uint8 **ppSig, uint32 &sigLen);



	bool
		m_bIsSessionIDSet;	/**< Flag to let us know if, during a key exchange, we need
							to set the sessionID equal to the big hash. We only set it during
							the first keyexchange */

	unsigned char
		*pV_C,				//ssh_string: V_C, the client's identification string (CR and LF excluded)
		*pV_S,				//ssh_string: V_S, the server's identification string (CR and LF excluded)
		*pI_C,				//ssh_string: the payload of the client's SSH_MSG_KEXINIT
		*pI_S,				//ssh_string: the payload of the server's SSH_MSG_KEXINIT
		*pK_S,				//ssh_string: Host key
		*pK_mpint,			//ssh_mpint: Shared secret in SSH mpint form
		*pf_mpint,			//ssh_mpint: exchange value sent by the server
		*pe_mpint,			//ssh_mpint: exchange value sent by the client
		*pHash,				//The biggie hash!
		*m_pSigOfH,			//The signature of hash H
		*m_pRSAsig,			/**< Holds the server's RSA signature */
		*m_pDSAsig,			/**< Holds the server's DSA signature */
		*m_pPublicKey,		/**< Pointer to the public key type string. */
		m_sessionID[SHA_DIGEST_LENGTH],
		m_H[SHA_DIGEST_LENGTH],
		m_serverHostKeyMD5[MD5_DIGEST_LENGTH],
		m_serverHostKeySHA[SHA_DIGEST_LENGTH];

	uint32
		m_sizeH,
		m_pSigOfHLen,			/**< Number of bytes in m_pSigOfH */
		m_sizeRSAsig,			/**< Number of bytes in m_pRSAsig */
		m_sizeDSAsig;			/**< Number of bytes in m_pDSAsig */

	BN_CTX
		*m_pBigNumContext;

	DSA 
		*m_pDSA;		/*<< Context to use for DSA public key stuff */
	RSA
		*m_pRSA;		/*<< Context to use for RSA public key stuff */

	BIGNUM
		*p_p,	//p - the 'p' in g^x mod p
		*p_g,	//g - the 'g' in g^x mod p
		*p_e,	//g^x mod p
		*p_x,	//Generated random number
		*p_f,	//Exchange value sent by the server
		*p_k,	//The shared secret
		/* These two are used for rsa public key stuff */
		*p_rsaE,
		*p_rsaN,
		/* These four are used for dss public key stuff */
		*p_dssP,
		*p_dssQ,
		*p_dssG,
		*p_dssY;


	KEYX_Type
		m_type;	//Specifies the type of diffe hellman keyexchange

	 PTsshSocket
		 * const m_pSshSocket; /**< Holds a pointer to the parent class, mainly so we can use
							 some of its public utility functions.. like makeSSHType_string */
};

#endif
