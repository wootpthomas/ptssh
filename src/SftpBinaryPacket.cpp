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

#include "SftpBinaryPacket.h"

#ifdef PTSSH_SFTP
#include "SSH2Types.h"
#include "SftpAttrs.h"

///////////////////////////////////////////////////////////////////////////////
SftpBinaryPacket::SftpBinaryPacket(uint32 localChannelNum):
BinaryPacket(localChannelNum)
{
}

///////////////////////////////////////////////////////////////////////////////
SftpBinaryPacket::~SftpBinaryPacket(void)
{
}

///////////////////////////////////////////////////////////////////////////////
/* From SFTP RFC:
All packets transmitted over the secure connection are of the
   following format:

       uint32           length
       byte             type
       uint32           request-id
           ... type specific fields ...

   'length'
      The length of the entire packet, excluding the length field
      itself, such that, for example, for a packet type containing no
      type specific fields, the length field would be 5, and 9 bytes of
      data would be sent on the wire.  (This is the packet format used
      in [RFC4253].)

      All packet descriptions in this document omit the length field for
      brevity; the length field MUST be included in any case.

      The maximum size of a packet is in practice determined by the
      client (the maximum size of read or write requests that it sends,
      plus a few bytes of packet overhead).  All servers SHOULD support
      packets of at least 34000 bytes (where the packet size refers to
      the full length, including the header above).  This should allow
      for reads and writes of at most 32768 bytes.

   'type'
      The type code for the packet.

   'request-id'
      Each request from the client contains a 'request-id' field.  Each
      response from the server includes that same 'request-id' from the
      request that the server is responding to.  One possible
      implementation is for the client to us a monotonically increasing
      request sequence number (modulo 2^32).  There is, however, no
      particular requirement the 'request-id' fields be unique.
*/
int32 
SftpBinaryPacket::init(uint32 sftpDataLen, uint8 sftpType, uint32 requestID, uint32 remoteChannelNum)
{
	int32 result = PTSSH_SUCCESS;
	uint32
		sftpPacketLen = 
			4 +          //length
			1 +          //type
			4 +          //request-id
			sftpDataLen, //Number of bytes of data in the Sftp packet
		BPLen = 
			1 +				//byte      SSH_MSG_CHANNEL_DATA
			4 +				//uint32    recipient channel
			4 + sftpPacketLen; //string    data

	if ( BinaryPacket::init(BPLen))
	{
		//Write the SSH specific header
		writeByte(   SSH_MSG_CHANNEL_DATA);   //SSH CHANNEL_DATA
		writeUint32( remoteChannelNum);       //SSH Channel number
		writeUint32( sftpPacketLen);          //SHH channel data length

		//Write the length, type and request-id
		writeUint32( sftpPacketLen - 4);      //SFTP packet length
		writeByte(   sftpType);               //SFTP Type
		writeUint32( requestID);              //SFTP requestID

		//Now the SSH Binary packet has the ssh header and sftp headers in place
		//Any additional writes* will be put in the proper place in the packet
	}
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}

///////////////////////////////////////////////////////////////////////////////
int32 
SftpBinaryPacket::writeAttr(SftpAttrs * const pAttrs)
{
	int32 result = PTSSH_SUCCESS;

	//Have the SftpAttrs object write its data to our write buffer
	//TODO: Bounds checking
	pAttrs->writeToPacketBuf( m_pWriteIter);
	m_pWriteIter += pAttrs->bufferSizeNeeded();

	return result;
}

#endif