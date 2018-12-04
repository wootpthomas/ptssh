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

#ifndef _PTSFTP
#define _PTSFTP

/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"
#include "Utility.h"

#ifndef _WIN32
#  include <fcntl.h>
#endif


/*************************
 * Forward Declarations
 ************************/
class PTssh;
class ChannelManager;
class SftpFileHandle;
class SftpDirHandle;
class SftpAttrs;
class SftpRequestMgr;

/*************************
 * Defines
 ************************/



typedef struct {
	uint8
		*pData;

	uint32 getID(){
		return PTSSH_htons32( (uint32*)(pData + 1));
	}

	uint32 getStatusCode() {
		return PTSSH_htons32( (uint32*)(pData + 5));
	}
} SSH_FXP_STATUS_STRUCT;


/**
 * Paul's SFTP main class. This class relies on the PTSSH class to create
 * it from an existing SSH session. This will help PTssh better make
 * efficient use of a single connection.
 *
 * The PTSftp class provides an implementation of the SSH File Transfer
 * Protocol. You should only need to spawn one single PTSftp object per
 * PTssh instance, as you can have multiple file handles open with PTSftp
 * and PTssh will then be able to make much more efficient use of available
 * bandwith by being able to fully pack more network packets to their maximum
 * size.
 *
 * If you want your shizz to make the best use of available bandwith, use one
 * instance of PTssh and if using SFTP, one instance of PTSftp derived from that
 * PTssh instance.
 */
class PTSftp
{
public:

	/**
	* This creates a new PTSftp object. This should only be called from within the 
	* PTssh object!
	* If you are a developer scratching your head wondering how to create a 
	* PTSftp object, you need to first create a PTssh object and successfully
	* connect to the SSH server of your choice. Once that's done, ask the PTssh
	* object for a PTSftp object:
	//The code here will change slightly if you are using the C-wrapper (DLL/SO)
	PTssh *pSSH = new PTssh();
	PTSftp *pSftp = NULL;
	//Create and initialize the PTssh object
	if ( pSSH && pSSH->init() == PTSSH_SUCCESS) 
	{
		//Connect to the SSH server, supplying the username, server address and port
		int32 result = pSSH->connect( ......);
		...    	//Make sure and test return result!

		//Authenticate
		result = pSSH->auth.... by password, public key... etc

		//After successful
		if ( result == PTSSH_SUCCESS)
		{
			result = pSSH->
	@param[in] pPTsshObj Pointer to a PTssh object
	@param[in] pChannelMrgObj Pointer to an internal PTssh object
	@param[in] channelNum Channel number that all data will traverse over
	@return Returns PTSSH_SUCCESS when all goes well ;p
	*/
	PTSftp(PTssh *pPTsshObj, ChannelManager *pChannelMrgObj, uint32 channelNum);

	/**
	* Typical destructor
	*/
	~PTSftp(void);

	/**
	* This will do the SFTP handshake (SSH_FXP_INIT). This lets the client and the
	* server figure out the highest version that both sides can use. PTSftp will then
	* use the highest version thats mutually supported by both sides.
	* If this returns success, you can now start making SFTP requests.
	@return Returns PTSSH_SUCCESS if all went well or an error otherwise
	*/
	int32 init();

	/**
	* Returns the SFTP protocol version the client and the server are using
	*/
	uint32 getSftpVersion() { return m_operatingSftpVersion; }

	/**
	* Opens a file and returns a handle that can then be used to perform
	* operations on that file
	*/
	int32 openFile(
		SftpFileHandle **ppSftpFileHandle,
		const char *fileName,
		uint32 pflags);

	/**
	* Closes the file handle and deletes the file handle's contents
	*/
	int32 closeFile(SftpFileHandle **ppSftpFileHandle);

	/**
	* Deletes the specified file. You should specify the full path to the file!
	*/
	int32 deleteFile(const char *pFileName);

	/**
	* Renames the specified file or directory. You should specify the full path
	* to the file in both old and new name
	*/
	int32 renameFileOrDir(const char *pOldName, const char *pNewName);

	/**
	* Creates the specified directory with the given attributes
	*/
	int32 makeDir(const char *pNewDir, SftpAttrs *pttrs);

	/**
	* Deletes the specified directory 
	*/
	int32 deleteDir(const char *pPath);

	/**
	* Opens a directory for reading. This will return a SftpDirHandle which you
	* can then use to query the contents of a directory.
	*/
	int32 openDir(
		SftpDirHandle **ppSftpDirHandle,
		const char *pPath);

	/**
	* Closes an open directory handle and deletes the SftpDirHandle object.
	*/
	int32 closeDir(SftpDirHandle **ppSftpDirHandle);

	/**
	* Gets file attributes for the specified file. In the case that the file
	* path points to a symlink, you can choose to get the attributes of the
	* file the symlink points to, or to get the attributes of the symlink */
	int32 getFileAttributes(const char *pPath, bool bFollowSymLinks, SftpAttrs *pAttrs);

	/**
	* Creates a symbolic link to the specified file
	*/
	int32 createSymLink(const char *pLinkPath, const char *pTargetPath);

protected:
	uint32 getNextRequestID();

private:
	
	PTssh
		* const m_pPTssh; /**< Pointer to the main PTssh instance that this class
						was derived from. We do not own this pointer*/
	SftpRequestMgr
		*m_pRequestMgr; /**< Pointer to our Sftp request manager. This helps us make
						simultaneous requests in a thread-safe way */

	ChannelManager
		* const m_pChannelMgr; /**< Pointer to the channel manager. We do not own this pointer
						so do not delete */
	uint32
		m_CNum,         /**< This is the number of the channel that our PTSftp class
						talks on */
		m_operatingSftpVersion, 
						/**< This is the SFTP version that the server and client must
						conform to. This is set during init() and is agreed upon by both
						sides. Its the highest version both mutually support*/

		m_requestedSftpVersion,
						/**< This is the SFTP protocol version that the user wants us to
						try to use. If this is not set, PTssh will use the highest SFTP
						protocol version that both client AND server both support */
		m_remoteChannelNum;
						/**< This is the channel number to use when sending packets. Its
						the remote end's channel number for our sftp session */
};

#endif
