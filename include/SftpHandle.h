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

#ifndef _SFTPHANDLE_H
#define _SFTPHANDLE_H



/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"

#ifdef PTSSH_SFTP
# include "SftpAttrs.h"

/*************************
 * Forward Declarations
 ************************/
class SftpRequestMgr;
class ChannelManager;


/**
* Defines a PTssh SFTP handle. The file and directory handles are derived
* from this base class.
*/
class SftpHandle {
public:
	/**
	* Creates a new PTssh sftp file handle
	*/
	SftpHandle(
		SftpRequestMgr * const pRequestMgr, 
		ChannelManager * const pChannelMgr, 
		uint32 cNum,
		uint32 remoteChannelNum,
		uint8 sftpVer);
	~SftpHandle();

	/**
	* Initialized the handle by copying the file handle into an internal
	* structure
	*/
	int32 init(uint8 *pSshHandleString);

	/**
	* Returns the length of the internal handle 
	*/
	uint32 getHandleLen() { return m_handleStrLen; }

	/**
	* Returns a pointer to the internal handle
	*/
	const uint8 * getHandleStr() { return m_pHandleStr; }

protected:
	uint8
		*m_pHandleStr;
	uint32
		m_handleStrLen,
		m_cNum,
		m_remoteChannelNum;
	SftpRequestMgr
		* const m_pRequestMgr;
	ChannelManager 
		* const m_pChannelMgr;
};

#endif /* PTSSH_SFTP */
#endif