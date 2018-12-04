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

#ifndef _SFTPFILEHANDLE_H
#define _SFTPFILEHANDLE_H



/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"

#ifdef PTSSH_SFTP
# include "SftpAttrs.h"
# include "SftpHandle.h"

/*************************
 * Forward Declarations
 ************************/
class SftpRequestMgr;
class ChannelManager;



/**
* Defines a PTssh SFTP file handle.
*/
class SftpFileHandle: public SftpHandle {
public:
	/**
	* Creates a new PTssh sftp file handle
	*/
	SftpFileHandle(
		SftpRequestMgr * const pRequestMgr, 
		ChannelManager * const pChannelMgr, 
		uint32 cNum,
		uint32 remoteChannelNum,
		uint8 sftpVer);
	~SftpFileHandle();

	/**
	* Reads the given number of bytes from the file into the
	* specified buffer.
	@param[in] pBuf Pointer to a buffer to hold data
	@param[in] bufLen Total number of bytes available in the buffer pointed
		to by pBuf. This is also teh number of bytes that we will try to read.
	@param[in] offset Offset from the beginning of the file to start reading from
	@param[out] bytesRead Set to the total number of bytes read
	@return Returns PTSSH_SUCCESS on success or an error
	*/
	int32 read(uint8 *pBuf, uint32 bufLen, uint64 offset, uint32 &bytesRead);

	/**
	* Writes the specified data in the buffer to the file
	*/
	int32 write(const uint8 *pBuf, uint32 bufLen);

	int32 getFileAttributes(SftpAttrs *pAttrs = NULL);

private:
	/**
	* If we asked for file data and the data was broken up into multiple
	* SSH packets, this will read all the packets into the specified buffer
	* provided there is enough room */
	int32 readRequestDataIntoBuffer(
		uint32 requestID, 
		uint8 *pBuf,
		uint8 *pBufEnd, 
		uint32 &bytesInRequest);

	bool
		bFileStatsSet;
	uint64
		m_fileWriteOffset;
	SftpAttrs
		m_attrs;
};

#endif /* PTSSH_SFTP */
#endif