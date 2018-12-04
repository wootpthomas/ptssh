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

/*************************
 * Includes
 ************************/
#include "SftpHandle.h"

#ifdef PTSSH_SFTP

#include "SSH2Types.h"
#include "SftpBinaryPacket.h"
#include "SftpRequestMgr.h"
#include "ChannelManager.h"
#include "Utility.h"
#include "PTsshLog.h"
#include "PTSftp.h"

#include <string.h>
#include <assert.h>

#if defined(WIN32)
#  if defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
#    define _CRTDBG_MAP_ALLOC
#    include <stdlib.h>
#    include <crtdbg.h>
#    define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#    define new DEBUG_NEW
#  endif
#endif


///////////////////////////////////////////////////////////////////////////////
SftpHandle::SftpHandle(
							   SftpRequestMgr * const pRequestMgr, 
							   ChannelManager * const pChannelMgr,
							   uint32 cNum,
							   uint32 remoteChannelNum,
							   uint8 sftpVer):
m_pRequestMgr(pRequestMgr),
m_pChannelMgr(pChannelMgr),
m_cNum(cNum),
m_remoteChannelNum(remoteChannelNum),
m_pHandleStr(0),
m_handleStrLen(0)
{

}

///////////////////////////////////////////////////////////////////////////////
SftpHandle::~SftpHandle()
{
	if ( m_pHandleStr)
	{
		delete m_pHandleStr;
		m_pHandleStr = NULL;
	}
}

///////////////////////////////////////////////////////////////////////////////
int32 
SftpHandle::init(uint8 *pSshHandleString)
{
	int32 result = PTSSH_SUCCESS;

	m_handleStrLen = PTSSH_htons32( (uint32*) pSshHandleString);
	m_pHandleStr = new uint8[m_handleStrLen];
	if ( m_pHandleStr)
		memcpy(m_pHandleStr, pSshHandleString + 4, m_handleStrLen);
	else
		result = PTSSH_ERR_CouldNotAllocateMemory;

	return result;
}



#endif