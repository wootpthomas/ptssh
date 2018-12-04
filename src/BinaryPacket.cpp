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


/**********************
 * Includes
 *********************/
#include "BinaryPacket.h"
#include "Utility.h"
#include "SSH2Types.h"
#include "PTsshLog.h"

#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif


#include <string.h>
#include <cstdlib>

/**********************
 * Initialize statics
 *********************/


///////////////////////////////////////////////////////////////////////////////
BinaryPacket::BinaryPacket(uint32 localChannelNumber):
m_localChannelNum( localChannelNumber),
m_BPLen(0),
m_pBP(0),
m_pWriteIter(0),
m_pReadIter(0)
{

}

///////////////////////////////////////////////////////////////////////////////
bool
BinaryPacket::init(void *pBuf, uint32 bufLen)
{
	if ( pBuf)
	{
		/* Here we are given a pointer to a BP that we read from the socket */
		m_pBP = (uint8*)pBuf;
		m_pReadIter = m_pBP + 5;

		//BufLen + 4 + padding length
		m_BPLen = bufLen; // + 4 + *((uint8*)(m_pBP + 4));

		//Verify the packet's size and make sure its valid
		if (  PTSSH_htons32( (uint32*)m_pBP ) + 4 > bufLen)
		{
			PTLOG((LL_error, "[BP] Bad packet length from SR\n"));
			return false;
		}
	}
	else
		return false;

	return true;
}

///////////////////////////////////////////////////////////////////////////////
/* This function is called when a BP is compressed. The compressing algorithm
* allocates space for the SSH headers and MAC length and padding. All we need
* to do is fill in the missing pieces.
*/
bool
BinaryPacket::init_deflate(void *pBuf, uint32 bufLen, uint32 encapsulatedDataLen)
{
	if ( pBuf)
	{
		int
			cipherBlockSize = 16,
			size = 
				4 +			//packet_length
				1 +			//padding_length
				encapsulatedDataLen;	//payload length
		uint8
			*pIter = (uint8*)pBuf,
			paddingLen = cipherBlockSize - (size % cipherBlockSize);

		//Adjust for minimum padding requirement
		if ( paddingLen < 4)
			paddingLen += cipherBlockSize;

		/* Here we are given a pointer to a buffer that the compression algorithm
		 * made, but it left us enough room for the packet_length and 
		 * padding_length fields and padding and MAC. We just need to fill in the
		 * SSH BP details*/
		m_pBP = (uint8*)pBuf;

		//Write the packet_length
		PTSSH_htons32(  size + paddingLen - 4, (uint32*)m_pBP );
		pIter += 4;

		//Write the padding_length
		*(pIter) = paddingLen;
	}
	else
		return false;

	return true;
}

///////////////////////////////////////////////////////////////////////////////
/* This function is called when a BP is un-compressed. The compressing algorithm
* allocates space for the SSH headers and MAC length and padding. All we need
* to do is fill in the missing pieces.
*/
bool
BinaryPacket::init_inflate(void *pBuf, uint32 bufLen, uint32 encapsulatedDataLen)
{	
	if ( pBuf)
	{
		int
			cipherBlockSize = 16,
			size = 
				4 +			//packet_length
				1 +			//padding_length
				encapsulatedDataLen;	//payload length
		uint8
			*pIter = (uint8*)pBuf,
			paddingLen = 0;

		/* Here we are given a pointer to a buffer that the compression algorithm
		 * made, but it left us enough room for the packet_length and 
		 * padding_length fields. We just need to fill in the SSH BP details*/
		m_pBP = (uint8*)pBuf;

		//Write the packet_length
		PTSSH_htons32(size + paddingLen - 4, (uint32*)m_pBP );
		pIter += 4;

		//Write the padding_length
		*(m_pBP + 4) = paddingLen;

		//Set the read pointer to correct spot
		m_pReadIter = m_pBP + 5;
	}
	else
		return false;

	return true;
}

///////////////////////////////////////////////////////////////////////////////
bool
BinaryPacket::init(uint32 dataLen)
{
	uint8
		cipherBlockSize = 16,
		paddingLen = 0,
		extraPadding = 0;

	/* Construct enough space in our m_pBP to hold the data */
	int
		binaryPackSize,
		size = 
			4 +			//packet_length
			1 +			//padding_length
			dataLen;	//payload length
	
	//Now we figure out the padding_length
	paddingLen = cipherBlockSize - (size % cipherBlockSize);
	if ( paddingLen < 4)	//SSH requires a minimum of 4 bytes of padding and max of 255
		paddingLen += cipherBlockSize;

#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
	/* For efficiency reasons with how our Compress class works, we make this
	 * BP large enough so that when we take this packet and compress it and if
	 * we encountered worst-case compression, the compressed data could still
	 * be placed in the original buffer that held the original un-compressed 
	 * data. We'll make sure that we have at least 16 bytes that we can expand
	 * into while still keeping enough room for the 4 bytes of required padding.*/
	extraPadding = 16;
#endif

	//Set the complete size we'd need to encapsulate a SSH binary packet
	binaryPackSize = size + paddingLen;
	m_BPLen = size + paddingLen + extraPadding;

	m_pBP = new uint8[m_BPLen];
	if ( m_pBP)
	{
		m_pWriteIter = m_pBP +5;

		
#ifdef _DEBUG
		uint8 *pChar = m_pBP;
		for (int i = 0; i < binaryPackSize; i++)
			*pChar++ = i;
#else
		/* For efficiency, we will only write to the padding area. 
		 * Should only write a max of cipherBlockSize bytes */
		uint8 *pChar = m_pBP + size;
		while ( pChar < (m_pBP + binaryPackSize))
			*pChar++ = rand() %256;
#endif
	}
	else
		return false;

	uint8 *pIter = m_pBP;
	
	//Set the SSH BP length
	PTSSH_htons32(binaryPackSize - 4, (uint32*)pIter );

	//Set the padding length
	pIter += 4;
	*pIter = paddingLen;
	
	return true;
}

///////////////////////////////////////////////////////////////////////////////
BinaryPacket::~BinaryPacket(void)
{
	if ( m_pBP)
	{
		delete m_pBP;
		m_pBP = NULL;
	}
}

///////////////////////////////////////////////////////////////////////////////
bool
BinaryPacket::writeByte(char c)
{
	if ( ! m_pWriteIter || m_pWriteIter > getPtrToLastByte() )
		return false;

	*m_pWriteIter++ = (uint8) c;
	return true;
}

///////////////////////////////////////////////////////////////////////////////
bool
BinaryPacket::writeBytes( uint8 *pData, uint32 size)
{
	if ( ! m_pWriteIter || (m_pWriteIter + size) > getPtrToLastByte() )
		return false;

	memcpy( m_pWriteIter, pData, size);
	m_pWriteIter += size;
	return true;
}

///////////////////////////////////////////////////////////////////////////////
bool
BinaryPacket::writeBoolean(bool value)
{
	if ( ! m_pWriteIter || m_pWriteIter > getPtrToLastByte() )
		return false;

	if (value)
		*m_pWriteIter++ = 0x1;
	else
		*m_pWriteIter++ = 0x0;
	
	return true;
}

///////////////////////////////////////////////////////////////////////////////
bool
BinaryPacket::writeUint32(uint32 value)
{
	if ( ! m_pWriteIter || (m_pWriteIter+4) > getPtrToLastByte() )
		return false;

	PTSSH_htons32(value, (uint32*)m_pWriteIter);
	m_pWriteIter += 4;
	
	return true;
}

///////////////////////////////////////////////////////////////////////////////
bool
BinaryPacket::writeUint64(uint64 value)
{
	if ( ! m_pWriteIter || (m_pWriteIter+8) > getPtrToLastByte() )
		return false;

	PTSSH_htons64(value, (uint64*)m_pWriteIter);
	m_pWriteIter += 8;
	
	return true;
}

///////////////////////////////////////////////////////////////////////////////
bool
BinaryPacket::writeString(const char *buf, uint32 bufLen)
{
	if ( ! m_pWriteIter || (m_pWriteIter + 4 + bufLen) > getPtrToLastByte() )
		return false;

	PTSSH_htons32(bufLen, (uint32*)m_pWriteIter);
	m_pWriteIter += 4;
	memcpy(m_pWriteIter, buf, bufLen);
	m_pWriteIter += bufLen;
	
	return true;
}

///////////////////////////////////////////////////////////////////////////////
bool
BinaryPacket::writeMPint(BIGNUM *pBN)
{
	int bytes;
	bool bLeadingZero = false;
	if ( BN_num_bits(pBN) % 8)
		bytes = BN_num_bytes(pBN);
	else
	{
		bytes = BN_num_bytes(pBN) + 1;
		bLeadingZero = true;
	}

	if ( ! m_pWriteIter || (m_pWriteIter + 4 + bytes) > getPtrToLastByte() )
		return false;

	PTSSH_htons32(bytes, (uint32*)m_pWriteIter);
	m_pWriteIter += 4;

	if (bLeadingZero) //This helps us have a leading 0 byte if its needed
	{
		*(m_pWriteIter++) = 0x0;
		bytes--;
	}
	
	BN_bn2bin(pBN, (unsigned char *) m_pWriteIter);
	m_pWriteIter += bytes;

	return true;
}

///////////////////////////////////////////////////////////////////////////////
int32
BinaryPacket::readByte(uint8 &value)
{
	int32 result = PTSSH_SUCCESS;
	if ( m_pReadIter) //TODO: check bounds && (m_pReadIter + ) <= 
		value = (*m_pReadIter++);
	else
		result = PTSSH_ERR_ReadPastEndOfBinaryPacket;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
BinaryPacket::readBool(bool &value)
{
	int32 result = PTSSH_SUCCESS;

	if ( m_pReadIter) //TODO: check bounds && (m_pReadIter + ) <= 
	{
		uint8 data = (*m_pReadIter++);
		if ( data == 0)
			value = false;
		else
			value = true;
	}
	else
		result = PTSSH_ERR_ReadPastEndOfBinaryPacket;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
BinaryPacket::readUint32(uint32 &value)
{
	int32 result = PTSSH_SUCCESS;

	if ( m_pReadIter)
	{
		value = PTSSH_htons32( *( (uint32*)m_pReadIter));
		m_pReadIter += 4;
	}
	else
		result = PTSSH_ERR_ReadPastEndOfBinaryPacket;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
BinaryPacket::readUint64(uint64 &value)
{
	int32 result = PTSSH_SUCCESS;
	if ( m_pReadIter)
	{
		PTSSH_htons64( *( (uint64*)m_pReadIter), &value);
		m_pReadIter += 8;
	}
	else
		result = PTSSH_ERR_ReadPastEndOfBinaryPacket;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32
BinaryPacket::readString(char **ppString, uint32 &strSize)
{
	int32 result = PTSSH_SUCCESS;
	if ( m_pReadIter)
	{
		PTSSH_htons32( *((uint32*)m_pReadIter), &strSize);
		if ( (m_pReadIter + 4 + strSize) <= (m_pBP + m_BPLen))
		{
			m_pReadIter += 4;
			if ( strlen > 0)
			{
				(*ppString) = new char[strSize+1];
				if ( *ppString)
				{
					memset( *ppString, 0x0, strSize+1);
					memcpy( *ppString, m_pReadIter, strSize);
				}
				else
					result = PTSSH_ERR_CouldNotAllocateMemory;
			}
			m_pReadIter += strSize;
		}
		else
			result = PTSSH_ERR_ReadPastEndOfBinaryPacket;
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
uint8 * const 
BinaryPacket::getChannelData()
{
	uint8 *pIter = this->m_pBP + 5;
	//pIter points to the message type at beginning of payload

	//What message type is it?
	switch ( *pIter)
	{
		case SSH_MSG_CHANNEL_DATA:
			//Point to the data
			pIter += 9;
			break;
		case SSH_MSG_CHANNEL_EXTENDED_DATA:
			//Point to the data
			pIter += 13;
			break;
		default:
			PTLOG((LL_error, "Error! Didn't expect this type of data\n"));
			pIter = NULL;
			break;
	}

	return pIter;
}

///////////////////////////////////////////////////////////////////////////////
void
BinaryPacket::setBP(uint8 *pBP)
{
	m_pBP = pBP;
	m_pReadIter = m_pBP + 5;	//Set our read iterator to the beginning of the payload
}

///////////////////////////////////////////////////////////////////////////////
uint8 *
BinaryPacket::getPtrToLastByte()
{
	uint8 *ptr = m_pBP + PTSSH_htons32( (uint32*)m_pBP) + 4 - *(m_pBP + 4);

	return ptr;
}

#ifdef PTSSH_SFTP
///////////////////////////////////////////////////////////////////////////////
uint8 *
BinaryPacket::sftpData()
{
	uint8 *pIter = this->m_pBP + 5;
	//pIter points to the message type at beginning of payload

	//What message type is it?
	if ( *pIter == SSH_MSG_CHANNEL_DATA)
	{
			//Point to the channel's SFTP data
			pIter += 13;
	}
	else  //Not a SFTP packet
		pIter = NULL;

	return pIter;
}

///////////////////////////////////////////////////////////////////////////////
uint32 
BinaryPacket::sftpDataLen()
{
	uint8 *pIter = this->m_pBP + 5;
	//pIter points to the message type at beginning of payload

	//What message type is it?
	if ( *pIter == SSH_MSG_CHANNEL_DATA)
	{
		//Point to the channel SSH string
		pIter += 9;
		return PTSSH_htons32( *( (uint32*)pIter));
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
uint8 
BinaryPacket::sftpType()
{	
	return *(this->m_pBP + 18);
}

///////////////////////////////////////////////////////////////////////////////
uint32 
BinaryPacket::sftpRequestID()
{
	uint8 *pIter = this->m_pBP + 19;
	return PTSSH_htons32( *( (uint32*)pIter));
}

#endif /* PTSSH_SFTP */