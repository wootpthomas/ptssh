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


#ifndef _MULTIPLECONNECTIONMGR
#define _MULTIPLECONNECTIONMGR


/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"
#include <pthread.h>


/*************************
* Forward declarations
*************************/
class LinkedList;
class PTssh;


typedef struct AUTHOBJ {
	const char
		*pUsername,
		*pHostAddress;
	char 
		*pPassword,
		*privateKeyPassphrase;
	uint8
		*pPublicKey,
		*pPrivateKey;
	uint16
		hostPort;
	uint32
		publicKeyLen,
		privateKeyLen;
	bool
		bPreferAuthByPublicKey;

	AUTHOBJ(const char *username, const char *hostAddr, uint16 remoteHostPort){
		pUsername = username;
		pHostAddress = hostAddr;
		hostPort = remoteHostPort;
		pPassword = 0;
		pPublicKey = 0;
		publicKeyLen = 0;
		pPrivateKey = 0;
		privateKeyLen = 0;
		privateKeyPassphrase = 0;
		bPreferAuthByPublicKey = true;
	}
} AuthObj;



class MultipleConnectionMgr
{
public:
	MultipleConnectionMgr(void);
	~MultipleConnectionMgr(void);

	/**
	* Initialize the multiple connection manager
	*/
	int32 init();

	/**
	* This will get a connection to the SSH server using data specified in the
	* authentication object. It will connect and authenticate if needed. Internally,
	* we also increment a reference counter so that we know how many objects are using
	* any particular PTssh object. 
	*/
	int32 getConnection(
		PTssh **ppPTssh,
		AuthObj *authData);

	/**
	* When you are done with a PTssh object and will no longer be using it, call this
	* function to let the MCM know that you are done. The MCM keeps a reference count
	* and when a PTssh object no longer has any references to it, the connection to 
	* that PTssh's remote server will be closed and the PTssh object deleted. 
	*/
	void returnConnection(PTssh *pPTssh);

private:

	typedef struct {
		pthread_mutex_t
			m_mutex;    /**< Mutex that makes the creation/authentication of this
						PTssh object thread-safe. This helps us keep from having
						two+ threads simultaneously create two+ PTssh objects for
						the same remote host/port and username */
		PTssh
			*pPTsshObj;
		uint32
			referenceCtr;
	} MCMNode;

	pthread_mutex_t
		m_listMutex;    /**< Mutex used to make our access to the MCM thread-safe. This
						also helps us in the case when multiple threads want the same
						connection and we need to wait for it to authenticate */

	LinkedList
		*m_pSSHList;     /**< List to each of the different MCMNodes.  */
};

typedef MultipleConnectionMgr MCM;   //Setup an alias

#endif
