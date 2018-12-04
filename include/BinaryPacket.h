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


#ifndef _BINARYPACKET
#define _BINARYPACKET

#include "PTsshConfig.h"
#include "Utility.h"
#include <openssl/bn.h>


/**
* The binary packet class is mainly used to provide extremely fast allocation
* of BinaryPackets. The idea is that whenever we send or recieve data for SSH,
* we always send and recive the data in the form of a binary packet. The makeup
* of a binary packet is:
\verbatim
  --------------------
  |   m_pPayload  -> Buffer that consists of:
  |      uint32    packet_length
  |      byte      padding_length
  |      byte[n1]  payload; n1 = packet_length - padding_length - 1
  |      byte[n2]  random padding; n2 = padding_length
  |      byte[m]   mac (Message Authentication Code - MAC); m = mac_length
  ---------------------

From SSH RFC:
      uint32    packet_length
      byte      padding_length
      byte[n1]  payload; n1 = packet_length - padding_length - 1
      byte[n2]  random padding; n2 = padding_length
      byte[m]   mac (Message Authentication Code - MAC); m = mac_length

      packet_length
         The length of the packet in bytes, not including 'mac' or the
         'packet_length' field itself.

      padding_length
         Length of 'random padding' (bytes).

      payload
         The useful contents of the packet.  If compression has been
         negotiated, this field is compressed.  Initially, compression
         MUST be "none".

      random padding
         Arbitrary-length padding, such that the total length of
         (packet_length || padding_length || payload || random padding)
         is a multiple of the cipher block size or 8, whichever is
         larger.  There MUST be at least four bytes of padding.  The
         padding SHOULD consist of random bytes.  The maximum amount of
         padding is 255 bytes.

      mac
         Message Authentication Code.  If message authentication has
         been negotiated, this field contains the MAC bytes.  Initially,
         the MAC algorithm MUST be "none".
 \endverbatim
*
* The structure of a BinaryPacket will be header stuff, followed by the payload area.
* We will store some needed details in the header, like the size of the BP. The payload
* area is variable in length. 
*/

class BinaryPacket
{
public:
	/**
	* Constructor to make a BP.
	* This class expects you to call its init() function after object creation to complete
	* the classes setup. */
	BinaryPacket(uint32 localChannelNumber = 0xFFFFFFFF);

	/**
	* Destructor */
	~BinaryPacket(void);

	/**
	* Call this to initialize the internals of the BP and specify a pointer
	* to a buffer to create a BP from data that was just read off of
	* the socket (reading and recieveing).
	@param pBuf Pointer to a buffer holding recieved data that we want to use this BP
		class to work on. If creating a new BP for sending, this should be NULL. We only
		use this to work on recieved packets.
	@param bufLen Length in bytes of the passed in buffer
	@return Returns true on successful init, false on failure
	*/
	bool init(void *pBuf, uint32 bufLen);

	/**
	* Call this to initialize the internals of a BP when building a BP from a buffer
	* that was returned as a result of another BP being compressed.
	*/
	bool init_deflate(void *pBuf, uint32 bufLen, uint32 encapsulatedDataLen);

	/**
	* Call this to initialize the internals of a BP when building a BP from a buffer
	* that was returned as a result of another BP being compressed.
	*/
	bool init_inflate(void *pBuf, uint32 bufLen, uint32 encapsulatedDataLen);

	/**
	* Call this to initialize the internals of the BP and specify the data length
	* of what we are encapsulating. We will use a blocksize of 16 to use for padding
	* the data out. This should work for all known encryptions.
	@param dataLen This is the total length of the data that is to be encapsulated
		and sent over the wire
	@return Returns true on successful init, false on failure
	*/
	bool init(uint32 dataLen);


	/***********************
	* Binary Packet "guts" functions. Use these to help fill in the:
	  |      uint32    packet_length
	  |      byte      padding_length
	  |      byte[n1]  payload; n1 = packet_length - padding_length - 1
	  |      byte[m]   mac (Message Authentication Code - MAC); m = mac_length
    ************************/
	
	/** 
	* Returns the type of SSH message
	*/
	uint8 getSSHMessageType() { return *(m_pBP + 5); }

	/**
	* Returns the channel number. Only valid if this packet is going to be sent
	* to a specific channel number on the remote end
	*/
	uint32 getChannelNum()
	{   return m_localChannelNum;   }

	/**
	* Returns the packet_length: 
	The length of the packet in bytes, not including 'mac' or the
    'packet_length' field itself.
	*/
	//uint32 getPacketLength() { return PTSSH_htons32( *((uint32*)m_pBP)); }


	/**
	* Returns the packet_length + the size of the packet_length field itself.
	* This is useful for getting the total number of bytes to decrypt or MAC sign.
	*/
	uint32 getTotalPacketLength() { return PTSSH_htons32( *((uint32*)m_pBP)) + 4; }

	/**
	* Returns the length of the encapsulated ChannelData + the length of the channel
	* data length field itself
	*/
	uint32 getChannelDataLen() { return PTSSH_htons32( *((uint32*)(m_pBP + 10)) ); }

	/**
	* Returns a pointer to the beginning of the channel's data
	*/
	uint8 * const getChannelData();

	/**
	* Returns a pointer to the beginning of the SSH binary packet buffer. You
	* should normally only be asking for this when you are ready to write the
	* packet to the socket and are NOT using encryption. 
	*/
	uint8 * getBP() { return m_pBP; }

	/**
	* Sets this BP to the specified pointer. Only use this if you just read
	* a binary packet off of the socket and are going to use this class to
	* read data.
	*/
	void setBP(uint8 *pBP);

	/**
	* Sets the length of the m_pBP buffer. You should NOT use this unless you 
	* really know what you're doing! */
	void setBPLen(uint8 len) { m_BPLen = len; }

	/**
	* Gets the length of the data being encapsulated in the SSH BP. This is
	* the length of the SSH payload, which does not include packet_length,
	* padding_length, random padding or MAC section. 
	*/
	uint32 getPayloadLen() { return PTSSH_htons32( *((uint32*)m_pBP)) - 1 - *(m_pBP + 4); }

	/**
	* returns a pointer to the data part of the payload. This directly after
	* the padding byte.
	*/
	uint8 * getPayloadPtr() { return m_pBP + 5; }

	/************************
	Writing functions: These are what you should use when creating a BP!
	DO NOT mix and match writes with reads and vice versa! You will seriously
	f#ck stuff up!
	************************/
	/**
	* Writes a SSH "byte" type using the given character to the BP and
	* then increments the writing pointer to the next position in the BP
	@return Returns true if there was enough room and we successfully wrote the data. 
		Returns false if there wasn't enough room to do the write.
	*/
	bool writeByte(char c);

	/**
	* Writes the given number of bytes starting from the specified pointer
	* incrementing the writing pointer as needed.
	@return Returns true if there was enough room and the bytes were copied
	*/
	bool writeBytes( uint8 *pData, uint32 size);

	/**
	* Writes a SSH "boolean" type using the given character to the BP and
	* then increments the writing pointer to the next position in the BP
	@return Returns true if there was enough room and we successfully wrote the data. 
		Returns false if there wasn't enough room to do the write.
	*/
	bool writeBoolean(bool value);

	/**
	* Writes a SSH "uint32" type using the given character pointer to the BP and
	* then increments the writing pointer to the next position in the BP
	@return Returns true if there was enough room and we successfully wrote the data. 
		Returns false if there wasn't enough room to do the write.
	*/
	bool writeUint32(uint32 value);

	/**
	* Writes a SSH "uint64" type using the given character pointer to the BP and
	* then increments the writing pointer to the next position in the BP
	@return Returns true if there was enough room and we successfully wrote the data. 
		Returns false if there wasn't enough room to do the write.
	*/
	bool writeUint64(uint64 value);

	/**
	* Writes a SSH "string" type using the given character pointer to the BP and
	* then increments the writing pointer to the next position in the BP
	@return Returns true if there was enough room and we successfully wrote the data. 
		Returns false if there wasn't enough room to do the write.
	*/
	bool writeString(const char *buf, uint32 bufLen);

	/**
	* Writes a SSH "mpint" type using the given character pointer to the BP and
	* then increments the writing pointer to the next position in the BP
	@return Returns true if there was enough room and we successfully wrote the data. 
		Returns false if there wasn't enough room to do the write.
	*/
	bool writeMPint(BIGNUM *pBN);

	/************************
	Writing functions: These are what you should use when creating a BP and
	then calling:
	   void setBP(uint8 *pBP);
	DO NOT mix and match writes with reads and vice versa! You will seriously
	f#ck stuff up!
	************************/
	/**
	* Resets the read pointer to the start of the BP
	*/
	void resetReadPointer() { m_pReadIter = m_pBP + 5; }

	/**
	* Reades a SSH "byte" type. The result of the read is a byte value. 
	* After the function is called, the read iterator is incremented appropriately.
	@param value Value of the byte read from the BinaryPacket
	@return Returns PTSSH_SUCCESS on success, otherwise an error code
	*/
	int32 readByte(uint8 &value);

	/**
	* Reades a SSH "boolean" type. The result of the read is a byte value. 
	* After the function is called, the read iterator is incremented appropriately.
	@param value Value of the byte read from the BinaryPacket
	@return Returns PTSSH_SUCCESS on success, otherwise an error code
	*/
	int32 readBool(bool &value);

	/**
	* Reades a SSH "uint32" type. The result of the read is a unsigned 32-bit value.
	* After the function is called, the read iterator is incremented appropriately.
	@param[out] value On success this is set to a uint32 value
	@return Returns PTSSH_SUCCESS on success, otherwise an error code
	*/
	int32 readUint32(uint32 &value);

	/**
	* Reades a SSH "uint64" type. The result of the read is a unsigned 64-bit value.
	* After the function is called, the read iterator is incremented appropriately.
	@param[out] value On success this is set to a uint64 value
	@return Returns PTSSH_SUCCESS on success, otherwise an error code
	*/
	int32 readUint64(uint64 &value);

	/**
	* Reads a SSH "string" type. If we were able to successfully read a string at the 
	* read iterator position, we return a pointer to the beginning of the string and
	* strLen is set to the string length, readSuccess is true. Finally, the read iterator
	* is incremented. The BP retains ownership of the pointer. Don't try and delete it.
	@param[in] ppString Pointer to a pointer that will hold the buffer of the read string
	@param[out] strLen Length of the returned buffer.
	@return Returns PTSSH_SUCCESS on success, otherwise an error code
	*/
	int32 readString(char **ppString, uint32 &strLen);

	/////**
	////* Writes a SSH "mpint" type using the given character pointer to the BP and
	////* then increments the writing pointer to the next position in the BP
	////@return Returns true if there was enough room and we successfully wrote the data. 
	////	Returns false if there wasn't enough room to do the write.
	////*/
	////bool writeMPint(BIGNUM *pBN);

	/**
	* Gets a pointer to the start of the Sftp data region of the packet
	*/
	uint8 * sftpData();

	/**
	* Gets the length of the buffer pointed to from a fall to sftpData()
	*/
	uint32 sftpDataLen();

	/**
	* Returns the type of SFTP packet that this packet encapsulates
	*/
	uint8 sftpType();

	/**
	* Returns the Sftp request ID of this packet
	*/
	uint32 sftpRequestID();

private:
	uint8 * getPtrToLastByte();


protected:
	uint32
		m_BPLen;			/**< Length of the Binary Packet buffer. This is NOT the length
							of the SSH BP! It will likely be a few bytes larger than the BP */

	uint8
		*m_pBP,				/**< This is a buffer large enough to be used for the
							encapsulated SSH BP */
		*m_pWriteIter,		/**< Used by the write*() functions. This helps keep track
							of where we will write to next time we call a write* function */
		*m_pReadIter;		/**< Used by the read*() functions. This helps keep track of where
							we read from in the packet's payload. */

	uint32
		m_localChannelNum;  /** This is the local channel number that this packet belongs to */
};

#endif
