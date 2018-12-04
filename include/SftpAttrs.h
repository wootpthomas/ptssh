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

#ifndef _SFTPATTRS_H
#define _SFTPATTRS_H


//
///*
//File Attributes
//
//   A new compound data type, 'ATTRS', is defined for encoding file
//   attributes.  The same encoding is used both when returning file
//   attributes from the server and when sending file attributes to the
//   server.
//
//       uint32   valid-attribute-flags
//       byte     type                   always present
//       uint64   size                   if flag SIZE
//       uint64   allocation-size        if flag ALLOCATION_SIZE
//       string   owner                  if flag OWNERGROUP
//       string   group                  if flag OWNERGROUP
//       uint32   permissions            if flag PERMISSIONS
//       int64    atime                  if flag ACCESSTIME
//       uint32   atime-nseconds            if flag SUBSECOND_TIMES
//       int64    createtime             if flag CREATETIME
//       uint32   createtime-nseconds       if flag SUBSECOND_TIMES
//       int64    mtime                  if flag MODIFYTIME
//       uint32   mtime-nseconds            if flag SUBSECOND_TIMES
//       int64    ctime                  if flag CTIME
//       uint32   ctime-nseconds            if flag SUBSECOND_TIMES
//       string   acl                    if flag ACL
//       uint32   attrib-bits            if flag BITS
//       uint32   attrib-bits-valid      if flag BITS
//       byte     text-hint              if flag TEXT_HINT
//       string   mime-type              if flag MIME_TYPE
//       uint32   link-count             if flag LINK_COUNT
//       string   untranslated-name      if flag UNTRANSLATED_NAME
//       uint32   extended-count         if flag EXTENDED
//       extension-pair extensions
//	   */



/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"

/*************************
 * Forward Declarations
 ************************/


class SftpAttrs{
public:
	SftpAttrs(uint8 sftpVersion = 3);
	~SftpAttrs();

	/**
	* Gets the size that this object will take up when written to a buffer 
	*/
	uint32 bufferSizeNeeded();

	/**
	* Gets the sftpVersion that this object is meant for */
	uint8 sftpVer() { return m_sftpVer; }

	/**
	* Sets/Gets the file size 
	*/
	void fileSize(uint64 size);
	uint64 fileSize();

	/**
	* Sets/Gets the uid (User ID)
	*/
	void uid(uint32 uid);
	uint32 uid();

	/**
	* Sets/Gets the gid (Group ID)
	*/
	void gid(uint32 gid);
	uint32 gid();

	/**
	* Sets/Gets the permissions
	*/
	void permissions(uint32 perm);
	uint32 permissions();

	/**
	* When we are ready to write this object on the wire as part of a binary packet,
	* we call this function from within the SftpBinaryPacket object. We then write
	* the data to the specified buffer
	*/
	void writeToPacketBuf(uint8 *pBuf);

	/**
	* When receiving a packet, we use this to let the class set its
	* properties appropriately from the buffer
	*/
	void getFromPacketBuffer(uint8 * pBuf);

private:
	uint8
		m_sftpVer;        /**< Tells us the sftp version that we need to build our attributes
						  object to suite */
	uint32
		m_validAttributeFlags,
		m_uid,
		m_gid,
		m_permissions,
		m_extendedCount;
	uint64
		m_size;

#if PTSSH_HIGHEST_SUPPORTED_SFTP_VERSION >= 4
public:
	uint8 type() { return m_type; }
	void type(uint8 type) { m_type = type; }
private:
	uint8
		m_textHint;
	uint32
		m_atime_nseconds,
		m_createTime_nseconds,
		m_mtime_nseconds,
		m_ctime_nseconds,
		m_attribBits,
		m_attribBitsValid,
		m_linkCount,
		//These tell us how long each of the matching char* strings are
		m_strLenOwner,
		m_strLenGroup,
		m_strLenACL,
		m_strLenMimeType,
		m_strLenUntranslatedName;
	uint64
		m_size;
	char
		*m_pOwner,
		*m_pGroup,
		*m_pACL,
		*m_pMimeType,
		*m_pUntranslatedName;
#endif

#if PTSSH_HIGHEST_SUPPORTED_SFTP_VERSION >= 5
#endif

#if PTSSH_HIGHEST_SUPPORTED_SFTP_VERSION >= 6
#endif

	/*Some Sftp versions use different size for these fields.
	v3 uses 32-bits
	v6 uses 64-bits
	*/
	union {
		uint64
			as64;
		uint32
			as32;
	} m_atime;
	
	union {
		uint64
			as64;
		uint32
			as32;
	} m_mtime;
};


#endif