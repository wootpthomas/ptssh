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

#ifndef _SFTPBINARYPACKET
#define _SFTPBINARYPACKET

/*************************
 * Includes
 ************************/
#include "BinaryPacket.h"


/*************************
 * Forward Declarations
 ************************/
class SftpAttrs;

class SftpBinaryPacket :
public BinaryPacket
{
public:
	SftpBinaryPacket(uint32 localChannelNum);
	~SftpBinaryPacket(void);

	/**
	* Initializes a new binary packet for the SFTP protocol with the SFTP
	* length, type and requestID
	@return Returns PTSSH_SUCCESS or an error otherwise
	*/
	int32 init(uint32 sftpDataLen, uint8 sftpType, uint32 requestID, uint32 remoteChannelNum);

	/**
	* Writes a SftpAttrs object to the binary packet
	*/
	int32 writeAttr(SftpAttrs * const pAttrs);
};

#endif