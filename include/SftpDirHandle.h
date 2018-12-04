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

#ifndef _SFTPDIRHANDLE_H
#define _SFTPDIRHANDLE_H



/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"
#include "SftpHandle.h"

#ifdef PTSSH_SFTP
# include "SftpAttrs.h"

/*************************
 * Forward Declarations
 ************************/
class SftpRequestMgr;
class ChannelManager;

struct _DIRECTORYITEM {
	char
		*pFileName,
		*pLongFileName;
	uint32
		fileNameLen,
		longFileNameLen;
	SftpAttrs
		attrs;
	_DIRECTORYITEM(){
		pFileName = NULL;
		pLongFileName = NULL;
		fileNameLen = 0;
		longFileNameLen = 0;
	}

	~_DIRECTORYITEM(){
		if ( pFileName)
		{
			delete pFileName;
			pFileName = NULL;
		}

		if ( pLongFileName)
		{
			delete pLongFileName;
			pLongFileName = NULL;
		}
	}
};

typedef struct _DIRECTORYITEM DirectoryItem;

class SftpDirHandle: public SftpHandle {
public:
	/**
	* Creates a new PTssh sftp directory handle
	*/
	SftpDirHandle(
		SftpRequestMgr * const pRequestMgr, 
		ChannelManager * const pChannelMgr, 
		uint32 cNum,
		uint32 remoteChannelNum,
		uint8 sftpVer);
	~SftpDirHandle();

	int32 readDir(DirectoryItem **ppDI, uint32 &itemCount);

private:

};

#endif /* PTSSH_SFTP */
#endif