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
#include "SftpAttrs.h"

#ifdef PTSSH_SFTP

#include "Utility.h"
#include "SSH2Types.h"
#include "PTsshLog.h"
#include <string.h>

///////////////////////////////////////////////////////////////////////////////
SftpAttrs::SftpAttrs(uint8 sftpVersion)
{
	//Set everything to 0
	memset( this, 0x0, sizeof(SftpAttrs));

	m_sftpVer = sftpVersion;
}

///////////////////////////////////////////////////////////////////////////////
SftpAttrs::~SftpAttrs()
{

}

///////////////////////////////////////////////////////////////////////////////
uint32
SftpAttrs::bufferSizeNeeded()
{
	uint32 objSize = 4;  //valid-attribute-flags

	/* Go through all the flags and add up the total byte size that this 
	 * object will take up
	 */
	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_SIZE)
		objSize += 8;

	if (m_validAttributeFlags & SSH_FILEXFER_ATTR_UIDGID)
		objSize += 
			4 + //uid
			4;  //gid

	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_PERMISSIONS)
		objSize += 4;

	if (m_validAttributeFlags & SSH_FILEXFER_ATTR_ACMODTIME)
		objSize += 
			4 + //atime
			4;  //mtime

	//Version 4+
#if PTSSH_HIGHEST_SUPPORTED_SFTP_VERSION >= 4
	if ( m_sftpVer >= 4)
	{
		objSize += 1; //type

		 if (m_validAttributeFlags & SSH_FILEXFER_ATTR_OWNERGROUP)
			objSize += 4 + m_strLenOwner + 4 + m_strLenGroup;

		if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_ACCESSTIME)
		{
			objSize += 8;
			if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
				objSize += 4;
		}

		if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_CREATETIME)
		{
			objSize += 8;
			if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
				objSize += 4;
		}

		if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_MODIFYTIME)
		{
			objSize += 8;
			if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
				objSize += 4;
		}

		if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_ACL)
			objSize += 4 + m_strLenACL;
	}
#endif

#if PTSSH_HIGHEST_SUPPORTED_SFTP_VERSION >= 5
	//Version 5+
	if ( m_sftpVer >= 5)
		if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_BITS)
			objSize += 4; //attrib-bits
#endif

#if PTSSH_HIGHEST_SUPPORTED_SFTP_VERSION >= 6
	//Version 6+
	if ( m_sftpVer >= 6)
	{
		if (m_validAttributeFlags & SSH_FILEXFER_ATTR_ALLOCATION_SIZE)
			objSize += 8;

		if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_BITS)
			objSize += 4;//attrib-bits-valid

		if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_CTIME)
		{
			objSize += 8;
			if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
				objSize += 4;
		}

		if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_TEXT_HINT)
			objSize += 1;

		if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_MIME_TYPE)
			objSize += 4 + m_strLenMimeType;

		if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_LINK_COUNT)
			objSize += 4;

		if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_UNTRANSLATED_NAME)
			objSize += 4 + m_strLenUntranslatedName;
	}
#endif

	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_EXTENDED)
	{
		objSize += 4;

		//TODO: Expand this when we begin supporting extension-pairs
	}

	return objSize;
}

///////////////////////////////////////////////////////////////////////////////
void
SftpAttrs::fileSize(uint64 size)
{
	m_validAttributeFlags |= SSH_FILEXFER_ATTR_SIZE;
	m_size = size;
}

///////////////////////////////////////////////////////////////////////////////
uint64
SftpAttrs::fileSize()
{
	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_SIZE)
		return m_size;

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
void
SftpAttrs::uid(uint32 uid)
{
	m_validAttributeFlags |= SSH_FILEXFER_ATTR_UIDGID;
	m_uid = uid;
}

///////////////////////////////////////////////////////////////////////////////
uint32
SftpAttrs::uid()
{
	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_UIDGID)
		return m_uid;

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
void
SftpAttrs::gid(uint32 gid)
{
	m_validAttributeFlags |= SSH_FILEXFER_ATTR_UIDGID;
	m_gid = gid;
}

///////////////////////////////////////////////////////////////////////////////
uint32
SftpAttrs::gid()
{
	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_UIDGID)
		return m_gid;

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
void
SftpAttrs::permissions(uint32 perm)
{
	m_validAttributeFlags |= SSH_FILEXFER_ATTR_PERMISSIONS;
	m_permissions = perm;
}

///////////////////////////////////////////////////////////////////////////////
uint32
SftpAttrs::permissions()
{
	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_PERMISSIONS)
		return m_permissions;

	return 0;
}



///////////////////////////////////////////////////////////////////////////////
void
SftpAttrs::writeToPacketBuf(uint8 *pBuf)
{
	PTSSH_htons32(m_validAttributeFlags, (uint32*)pBuf);
	pBuf += 4;
	
	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_SIZE)
	{
		PTSSH_htons64( bufferSizeNeeded(), (uint64*)pBuf);
		pBuf += 8;
	}

	if (m_validAttributeFlags & SSH_FILEXFER_ATTR_UIDGID)
	{
		PTSSH_htons32( m_uid, (uint32*)pBuf);
		pBuf += 4;
		PTSSH_htons32( m_gid, (uint32*)pBuf);
		pBuf += 4;
	}

	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_PERMISSIONS)
	{
		PTSSH_htons32( m_permissions, (uint32*)pBuf);
		pBuf += 4;
	}

	if (m_validAttributeFlags & SSH_FILEXFER_ATTR_ACMODTIME)
	{
		PTSSH_htons32( m_atime.as32, (uint32*)pBuf);
		pBuf += 4;
		PTSSH_htons32( m_mtime.as32, (uint32*)pBuf);
		pBuf += 4;
	}

	////Version 4+
	//if ( m_sftpVer >= 4)
	//{
	//	objSize += 1; //type
	//	if (m_validAttributeFlags & SSH_FILEXFER_ATTR_OWNERGROUP)
	//		objSize += 4 + m_strLenOwner + 4 + m_strLenGroup;

	//	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_ACCESSTIME)
	//	{
	//		objSize += 8;
	//		if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
	//			objSize += 4;
	//	}

	//	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_CREATETIME)
	//	{
	//		objSize += 8;
	//		if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
	//			objSize += 4;
	//	}

	//	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_MODIFYTIME)
	//	{
	//		objSize += 8;
	//		if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
	//			objSize += 4;
	//	}

	//	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_ACL)
	//		objSize += 4 + m_strLenACL;

	//	//Version 5+
	//	if ( m_sftpVer >= 5)
	//	{
	//		if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_BITS)
	//			objSize += 4; //attrib-bits

	//		//Version 6+
	//		if ( m_sftpVer >= 6)
	//		{
	//			if (m_validAttributeFlags & SSH_FILEXFER_ATTR_ALLOCATION_SIZE)
	//				objSize += 8;

	//			if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_BITS)
	//				objSize += 4;//attrib-bits-valid

	//			if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_CTIME)
	//			{
	//				objSize += 8;
	//				if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES)
	//					objSize += 4;
	//			}

	//			if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_TEXT_HINT)
	//				objSize += 1;

	//			if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_MIME_TYPE)
	//				objSize += 4 + m_strLenMimeType;

	//			if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_LINK_COUNT)
	//				objSize += 4;

	//			if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_UNTRANSLATED_NAME)
	//				objSize += 4 + m_strLenUntranslatedName;
	//		}
	//	}
	//}


	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_EXTENDED)
	{
		PTSSH_htons32( m_extendedCount, (uint32*)pBuf);
		pBuf += 4;

		//TODO: Expand this when we begin supporting extension-pairs
	}
}

///////////////////////////////////////////////////////////////////////////////
/* Sftp v3
   	uint32   flags
   	uint64   size           present only if flag SSH_FILEXFER_ATTR_SIZE
   	uint32   uid            present only if flag SSH_FILEXFER_ATTR_UIDGID
   	uint32   gid            present only if flag SSH_FILEXFER_ATTR_UIDGID
   	uint32   permissions    present only if flag SSH_FILEXFER_ATTR_PERMISSIONS
   	uint32   atime          present only if flag SSH_FILEXFER_ACMODTIME
   	uint32   mtime          present only if flag SSH_FILEXFER_ACMODTIME
   	uint32   extended_count present only if flag SSH_FILEXFER_ATTR_EXTENDED
   	string   extended_type
   	string   extended_data
   	...      more extended data (extended_type - extended_data pairs),
   		   so that number of pairs equals extended_count
*/
void
SftpAttrs::getFromPacketBuffer(uint8 * pBuf)
{
	m_validAttributeFlags = PTSSH_htons32( (uint32*)pBuf);
	pBuf += 4;
	
	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_SIZE)
	{
		PTSSH_htons64( *(uint64*)pBuf, &m_size);
		pBuf += 8;
	}

	if (m_validAttributeFlags & SSH_FILEXFER_ATTR_UIDGID)
	{
		m_uid = PTSSH_htons32( (uint32*)pBuf);
		pBuf += 4;
		m_gid = PTSSH_htons32( (uint32*)pBuf);
		pBuf += 4;
	}

	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_PERMISSIONS)
	{
		m_permissions = PTSSH_htons32( (uint32*)pBuf);
		pBuf += 4;
	}

	if (m_validAttributeFlags & SSH_FILEXFER_ATTR_ACMODTIME)
	{
		m_atime.as32 = PTSSH_htons32( (uint32*)pBuf);
		pBuf += 4;
		m_mtime.as32 = PTSSH_htons32( (uint32*)pBuf);
		pBuf += 4;
	}

	////Version 4+
	//if ( m_sftpVer >= 4)
	//{

	if ( m_validAttributeFlags & SSH_FILEXFER_ATTR_EXTENDED)
	{
		m_extendedCount = PTSSH_htons32( (uint32*)pBuf);
		pBuf += 4;

		//TODO: Expand this when we begin supporting extension-pairs
		PTLOG((LL_warning, "Extra file attributes detected but not used!\n"));
	}
}

#endif