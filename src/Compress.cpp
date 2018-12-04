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


#include "PTsshConfig.h"

#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
# include "Compress.h"
# include <string.h>
# include <stdio.h>

# include "Utility.h"
# include "SSH2Types.h"
# include "PTsshLog.h"
# include "BinaryPacket.h"


///////////////////////////////////////////////////////////////////////////////
Compress::Compress(int compressLevel):
m_compressLevel(compressLevel),
m_bIsInitialized(false),
m_compBufSize(0),
m_pCompBuf(0)
{
	m_strm.zalloc = Z_NULL;
	m_strm.zfree = Z_NULL;
	m_strm.opaque = Z_NULL;

	memset( &m_strm, 0, sizeof(z_stream));
}

///////////////////////////////////////////////////////////////////////////////
Compress::~Compress(void)
{
}

///////////////////////////////////////////////////////////////////////////////
int32
Compress::init(bool bIsCompression)
{
	int32 result;

	if ( bIsCompression)
		result = deflateInit( &m_strm, m_compressLevel);
	else
		result = inflateInit( &m_strm);

	if ( result != Z_OK)
		result = PTSSH_ERR_ZlibInitFailed;
	else
	{
		if ( bIsCompression)
		{
			//For compression, we will allocate a buffer to help us make compression more efficient
			m_compBufSize = PTSSH_MAX_PACKET_SIZE + 64;
			m_pCompBuf = new uint8[m_compBufSize];
			if ( ! m_pCompBuf)
				return PTSSH_ERR_CouldNotAllocateMemory;
		}

		m_bIsInitialized = true;
		result = PTSSH_SUCCESS;
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
/*
Let's be smart about inflating things. In the world of ssh, theres going to be
two types of packets, small and large. The small packets will rarely ever be really
big, with few exceptions. The majority of the time, the packets that are friggin'
huge are SSH_MSG_CHANNEL_DATA packets. One problem we have inflation-wise is that
we don't know how big of a buffer to use ahead of time... but if you look at the data
you are messing with, it should be obvious that the channel data tells you how big it
actually is early on. Channel data is stored in an SSH_string type, and the first few
bytes tell us how much data we expect.

So with that in mind, we inflate packets into a buffer on the stack and after we
inflate the packet fully we allocate a buffer to copy it into to return to calling
function.
IF the packet is a SSH_MSG_CHANNEL_DATA, when we run out of space on the stack buffer
we then look and see what type of packet it is. We then do NO guesswork as to the
final packet size, we read it from the packet, allocate a buffer large enough to hold
it and return it.
*/
int32
Compress::inflate(
		uint8 *pDataIn,
		uint32 dataInSize,
		uint8 **pDataOut,
		uint32 &expandedDataLen,
		uint32 &totalDataOutBufSize)
{
	int 
		status,
		result = PTSSH_SUCCESS;

	if ( ! m_bIsInitialized)
		return PTSSH_ERR_NotInitializedYet;
	uint8
		tempBuf[PTSSH_COMP_TEMP_BUF_LEN],    //Buffer to use for temp inflation
		*pIter;
	bool
		bFirstRun = true;

	expandedDataLen = 0;

	m_strm.next_in = pDataIn;
	m_strm.avail_in = dataInSize;
	pIter = tempBuf;

	m_strm.next_out = pIter;
	m_strm.avail_out = PTSSH_COMP_TEMP_BUF_LEN;

	status = ::inflate( &m_strm, Z_SYNC_FLUSH);
	if ( status != Z_OK)
	{
		getZlibError(status);
		return PTSSH_ERR_ZlibCompressionFailure;
	}
	else
	{   
		if (m_strm.avail_in)
		{
			uint32
				offset = 4 + 1;  //Leave room for packet_len, padding_len
			/* Alright, the first bit of inflation went ok, inspect the packet so that
			 * we can make an educated guess as to the packet's decompressed (inflated)
			 * size. This helps us only make ONE memory allocation ;p */
			if (  *pIter == SSH_MSG_CHANNEL_EXTENDED_DATA) {
				PTLOG((LL_debug3, "extended data\n"));
			}

			if ( *pIter == SSH_MSG_CHANNEL_DATA)
			{
				/* SSH_MSG_CHANNEL_DATA packet fields
				4 + uint32    packet_len
				1 + byte      padding_len
				1 + byte      SSH_MSG_CHANNEL_DATA
				4 +	uint32    recipient channel
				4 + string    data
				*/
				uint32
					channelDataLen = PTSSH_htons32( (uint32*)(pIter+5) );
				/* To correctly calculate the exact buffer size we need, based off the channel
				 * data length, we have to calculate it as follows:
				 (4) packet_len + 
				 (1) padding_len + 
				 (1) packet_type + 
				 (4) uint32 channel number +
				 (4) uint32 channel data len field +
				 channelDataLen
				 */
				totalDataOutBufSize = 4 + 1 + 1 + 4 + 4 + channelDataLen;
				*pDataOut = new uint8[ totalDataOutBufSize ];
			}
			else if (*pIter == SSH_MSG_CHANNEL_EXTENDED_DATA)
			{
				/* SSH_MSG_CHANNEL_EXTENDED_DATA packet fields
				4 + uint32    packet_len
				1 + byte      padding_len
				1 + byte      SSH_MSG_CHANNEL_DATA
				4 +	uint32    recipient channel
				4 + uint32    data_type_code
				4 + string    data
				*/
				uint32
					channelDataLen = PTSSH_htons32( (uint32*)(pIter+9) );
				/* To correctly calculate the exact buffer size we need, based off the channel
				 * data length, we have to calculate it as follows:
				 (4) packet_len + 
				 (1) padding_len + 
				 (1) packet_type + 
				 (4) uint32 channel number +
				 (4) data type code +
				 (4) uint32 channel data len field +
				 channelDataLen
				 */
				totalDataOutBufSize = 4 + 1 + 1 + 4 + 4 + 4 + channelDataLen;
				*pDataOut = new uint8[ totalDataOutBufSize ];
			}
			else
			{
				totalDataOutBufSize = dataInSize*2 + offset;
				*pDataOut = new uint8[totalDataOutBufSize];
			}

			if ( ! *pDataOut)
				return PTSSH_ERR_CouldNotAllocateMemory;

			//Copy in the little bit of decompressed data into the packet...
			//Leaving room for packet_len, padding_len
			memcpy( *pDataOut + offset, tempBuf, PTSSH_COMP_TEMP_BUF_LEN - m_strm.avail_out);

			//Put our pointer in the next spot to write to for rest of decompression
			pIter = *pDataOut + offset + (PTSSH_COMP_TEMP_BUF_LEN - m_strm.avail_out);

			//Get the output part of the stream ready
			m_strm.next_out = pIter;
			m_strm.avail_out = totalDataOutBufSize - (5 + (PTSSH_COMP_TEMP_BUF_LEN - m_strm.avail_out));
			status = ::inflate( &m_strm, Z_SYNC_FLUSH);
			if ( status != Z_OK)
			{
				getZlibError(status);
				delete *pDataOut;
				*pDataOut = NULL;
				totalDataOutBufSize = 0;

				return PTSSH_ERR_ZlibCompressionFailure;
			}

			if (m_strm.avail_in)
			{
				PTLOG((LL_error, "Error! still more to inflate!\n"));
			}

			// Subtract pakcet_len and padding_len fields and any un-used buffer space
			expandedDataLen =  (totalDataOutBufSize - 5) - m_strm.avail_out;
		}
		else
		{
			//Looks like PTSSH_COMP_TEMP_BUF_LEN bytes was enough space to fully inflate packet!
			totalDataOutBufSize = (PTSSH_COMP_TEMP_BUF_LEN - m_strm.avail_out) + 5;
			*pDataOut = new uint8[ totalDataOutBufSize ];
			if ( ! *pDataOut)
				return PTSSH_ERR_CouldNotAllocateMemory;

			//Copy inflated data to its new home in a pre-built BinaryPacket buffer
			memcpy( *pDataOut + 5, tempBuf, PTSSH_COMP_TEMP_BUF_LEN - m_strm.avail_out);

			expandedDataLen =  totalDataOutBufSize-5;
		}
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////
void
Compress::getZlibError(int status)
{
	switch (status) {
    case Z_ERRNO:
        PTLOG((LL_error, "error reading ???\n"));
        break;
    case Z_STREAM_ERROR:
        PTLOG((LL_error, "invalid compression level\n"));
        break;
    case Z_DATA_ERROR:
        PTLOG((LL_error, "invalid or incomplete deflate data\n"));
        break;
    case Z_MEM_ERROR:
        PTLOG((LL_error, "out of memory\n"));
        break;
    case Z_VERSION_ERROR:
        PTLOG((LL_error, "zlib version mismatch!\n"));
		break;
	case Z_NEED_DICT:
	default:
		PTLOG((LL_error, "zlib data error!\n"));
    }
}

#ifdef PTSSH_COMP_USE_COMP_TEMP_BUF
///////////////////////////////////////////////////////////////////////////////
int32
Compress::deflate(BinaryPacket *pBP)
{
	int
		result = PTSSH_SUCCESS,
		status;
	uint8
		*pIter = NULL,
		paddingLen = 0x0,
		cipherBlockSize = 16;
	uint32
		newPacketSize = 0x0;

	if ( ! m_bIsInitialized)
		return PTSSH_ERR_NotInitializedYet;

	/* Make packet large enough to handle worst-case compression.
	* Packet_len (4) + padding (1) + payload (dataInSize + (zlib header) 4 + slop 16) + required padding (4)	*/
	m_strm.next_in = pBP->getPayloadPtr();
	m_strm.avail_in = pBP->getPayloadLen();

	//We leave the packet_len (4) and padding_len (1) fields intact + possible padding (15)
	m_strm.next_out = m_pCompBuf;
	m_strm.avail_out = m_compBufSize;

	status = ::deflate( &m_strm, Z_SYNC_FLUSH);
	if ( status != Z_OK)
	{
		getZlibError(status);

		return PTSSH_ERR_ZlibCompressionFailure;
	}

	if (m_strm.avail_in)
	{
		PTLOG((LL_error, "[Comp] Not enough room to deflate!\n"));
		return PTSSH_ERR_ZlibCompressionFailure;
	}

	if (m_strm.avail_out == 0)
	{
		//Might be a few bytes left in deflate buffer
		uint8
			bytes[16];
		memset(bytes, 0x0, 16);

		m_strm.next_out = bytes;
		m_strm.avail_out = 16;
		status = ::deflate( &m_strm, Z_SYNC_FLUSH);
		if ( status != Z_OK)
		{
			getZlibError(status);
			return PTSSH_ERR_ZlibCompressionFailure;
		}
		else
		{
			if ( 16 - m_strm.avail_out > 0)
			{
				PTLOG((LL_error, "[Comp] Needed more space for deflating!\n"));
			}
		}
	}

	//Build the new BP in place of the old one
	pIter = pBP->getBP();
	//Write in the new packet size = packet_size + padding + payload
	newPacketSize = 4 + 1 + (m_compBufSize - m_strm.avail_out);

	//Figure out padding
	paddingLen = cipherBlockSize - (newPacketSize % cipherBlockSize);
	if ( paddingLen < 4)	//SSH requires a minimum of 4 bytes of padding and max of 255
		paddingLen += cipherBlockSize;

	*((uint32*)pIter) = PTSSH_htons32( 1 + (m_compBufSize - m_strm.avail_out) + paddingLen);
	pIter += 4;
	*pIter++ = paddingLen;

	memcpy( pIter, m_pCompBuf, m_compBufSize - m_strm.avail_out);

	/* We don't worry about writing crap to the padding area. Because we don't clear this buffer,
	 * it'll likely have plenty of random bytes in our padding area */

	return result;
}
#else
///////////////////////////////////////////////////////////////////////////////
int32
Compress::deflate(
		uint8 *pDataIn,
		uint32 dataInSize,
		uint8 **pDataOut,
		uint32 &compressedDataLen,
		uint32 &pDataOutLen)
{
	int
		result = PTSSH_SUCCESS,
		status;
	uint8
		*pIter = NULL,
		paddingLen = 0x0;
	uint32
		availCompressedBufSpace = 0x0;

	if ( ! m_bIsInitialized)
		return PTSSH_ERR_NotInitializedYet;

	/* Make packet large enough to handle worst-case compression.
	* Packet_len (4) + padding (1) + payload (dataInSize + (zlib header) 4 + slop 16) + required padding (4)	*/
	availCompressedBufSpace = dataInSize + 4 + 16;
	pDataOutLen = 4 + 1 + availCompressedBufSpace + 4;

	//Make the buffer evenly divisible by the cipher block size
	paddingLen = pDataOutLen % 16;
	if (paddingLen > 0)
	{
		paddingLen = 16 - paddingLen;
		pDataOutLen += paddingLen;
	}

	m_strm.next_in = pDataIn;
	m_strm.avail_in = dataInSize;
	*pDataOut = new uint8[pDataOutLen];
	if ( ! *pDataOut)
		return PTSSH_ERR_CouldNotAllocateMemory;

	//We leave the packet_len (4) and padding_len (1) fields intact + possible padding (15)
	pIter = *pDataOut + 5;
	m_strm.next_out = pIter;
	m_strm.avail_out = availCompressedBufSpace;

	status = ::deflate( &m_strm, Z_SYNC_FLUSH);
	if ( status != Z_OK)
	{
		getZlibError(status);

		delete m_strm.next_out;
		return PTSSH_ERR_ZlibCompressionFailure;
	}

	if (m_strm.avail_in)
	{
		PTLOG((LL_error, "[Comp] Not enough room to deflate!\n"));
		return PTSSH_ERR_ZlibCompressionFailure;
	}

	if (m_strm.avail_out == 0)
	{
		//Might be a few bytes left in deflate buffer
		uint8
			bytes[16];
		memset(bytes, 0x0, 16);

		m_strm.next_out = bytes;
		m_strm.avail_out = 16;
		status = ::deflate( &m_strm, Z_SYNC_FLUSH);
		if ( status != Z_OK)
		{
			getZlibError(status);

			delete *pDataOut;
			*pDataOut = NULL;
			return PTSSH_ERR_ZlibCompressionFailure;
		}
		else
		{
			if ( 16 - m_strm.avail_out > 0)
			{
				PTLOG((LL_error, "[Comp] Needed more space for deflating!\n"));
			}
		}
	}

	compressedDataLen = availCompressedBufSpace - m_strm.avail_out;

	return result;
}
#endif /* PTSSH_COMP_USE_COMP_TEMP_BUF */

#endif /* PTSSH_ZLIB */
