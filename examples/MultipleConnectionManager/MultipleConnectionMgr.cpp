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
#include "PTssh.h"
#include "MultipleConnectionMgr.h"
#include "LinkedList.h"
#include <string.h>

///////////////////////////////////////////////////////////////////////////////
MultipleConnectionMgr::MultipleConnectionMgr(void):
m_pSSHList(0)
{
}

///////////////////////////////////////////////////////////////////////////////
MultipleConnectionMgr::~MultipleConnectionMgr(void)
{
	if ( m_pSSHList)
	{
		delete m_pSSHList;
		m_pSSHList = NULL;
	}
}

///////////////////////////////////////////////////////////////////////////////
int32
MultipleConnectionMgr::init()
{
	pthread_mutex_init( &m_listMutex, 0);

	m_pSSHList = new LinkedList();
	if ( ! m_pSSHList)
		return PTSSH_ERR_CouldNotAllocateMemory;

	return PTSSH_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
int32
MultipleConnectionMgr::getConnection(
	PTssh **ppPTssh,
	AuthObj *pAuthData)
{
	MCMNode 
		*pMCMNode = NULL;
	int32 
		result;
	if ( ! pAuthData)
		return PTSSH_ERR_NullPointer;

	pthread_mutex_lock( &m_listMutex);
	for (uint32 i = 0; i < m_pSSHList->size(); i++)
	{
		pMCMNode = (MCMNode*)m_pSSHList->peek(i);
		*ppPTssh = pMCMNode->pPTsshObj;
		if ( *ppPTssh && 
			(*ppPTssh)->getRemoteHostPort() == pAuthData->hostPort &&
			strcmp( (*ppPTssh)->getRemoteHostAddress(), pAuthData->pHostAddress) == 0 &&
			strcmp( (*ppPTssh)->getUsername(), (const char *)pAuthData->pUsername) == 0)
		{
			break;
		}
		else
			pMCMNode = NULL;
	}

	/* If we get here and the pMCMNode is NULL, we need to create a new PTssh obj. We are prepping
	* a PTssh object to be placed in our list */
	if (pMCMNode == NULL)
	{
		result = PTSSH_ERR_CouldNotAllocateMemory;
		pMCMNode = new MCMNode();
		if (pMCMNode)
		{
			pMCMNode->referenceCtr = 0;
			pthread_mutex_init( &pMCMNode->m_mutex, 0);
			pMCMNode->pPTsshObj = new PTssh();
			if ( pMCMNode->pPTsshObj)
			{
				result = pMCMNode->pPTsshObj->init(pAuthData->pUsername, pAuthData->pHostAddress, pAuthData->hostPort);
				if ( result == PTSSH_SUCCESS)
				{
					/* All is good with the node. Add the node to the list */
					m_pSSHList->insertAtEnd( pMCMNode);
				}
				else
				{
					delete pMCMNode->pPTsshObj;
					delete pMCMNode;
					pMCMNode = NULL;
					return result;
				}
			}
			else
			{
				delete pMCMNode;
				pMCMNode = NULL;
				return result;
			}
		}
	}

	pthread_mutex_unlock( &m_listMutex);

	/* Ok, now we are going to acquire the lock to the PTssh object we want and see if
	its connected and up & running. If it isn't, we'll connect it up */
	pthread_mutex_lock( &pMCMNode->m_mutex);
		if ( ! pMCMNode->pPTsshObj->isConnected())
		{
			result =  pMCMNode->pPTsshObj->connectUp();
			if ( result != PTSSH_SUCCESS)
				goto exitError;
		}

		if ( ! pMCMNode->pPTsshObj->isAuthenticated())
		{
			bool bResult = false;
			//Try and authenticate with any available methods
			if ( pAuthData->bPreferAuthByPublicKey && 
				pAuthData->pPublicKey &&
				pAuthData->publicKeyLen > 0 &&
				pAuthData->pPrivateKey &&
				pAuthData->privateKeyLen > 0)
			{
				//Authenticate using the public/private key pair
				result = pMCMNode->pPTsshObj->authByPublicKey(
					pAuthData->pPublicKey,
					pAuthData->publicKeyLen,
					pAuthData->pPrivateKey,
					pAuthData->privateKeyLen,
					pAuthData->privateKeyPassphrase);
			}
			else if ( pMCMNode->pPTsshObj->isAuthSupported(PTsshAuth_Password, bResult) == PTSSH_SUCCESS &&
				bResult && pAuthData->pPassword)
			{
				result = pMCMNode->pPTsshObj->authByPassword(
					pAuthData->pPassword);
			}
			else
				result = PTSSH_ERR_NoAvailableAuthenticationMethod;

			if ( result != PTSSH_SUCCESS)
				goto exitError;
		}
	
		//If we get here, the PTssh object we have is alive and well
		*ppPTssh = pMCMNode->pPTsshObj;
		//Increment our reference counter
		pMCMNode->referenceCtr++;
	pthread_mutex_unlock( &pMCMNode->m_mutex);

	return PTSSH_SUCCESS;

exitError:
	*ppPTssh = NULL;
	pthread_mutex_unlock( &pMCMNode->m_mutex);
	
	return result;
}

///////////////////////////////////////////////////////////////////////////////
void
MultipleConnectionMgr::returnConnection(PTssh *pPTssh)
{
	MCMNode 
		*pMCMNode = NULL;
	uint32 
		i = 0;

	pthread_mutex_lock( &m_listMutex);
	for ( ; i < m_pSSHList->size(); i++)
	{
		pMCMNode = (MCMNode*)m_pSSHList->peek(i);
		if ( pPTssh == pMCMNode->pPTsshObj)
			break;
		else
			pMCMNode = NULL;
	}

	if ( pMCMNode)
	{
		pthread_mutex_lock( &pMCMNode->m_mutex);
			pMCMNode->referenceCtr--;
			if( pMCMNode->referenceCtr == 0)
			{
				printf("No more references to 0x%p, shutting it down\n", pMCMNode->pPTsshObj);
				//Remove the node from the list, its time to kill this PTssh object: no one's using it
				m_pSSHList->remove( i);
				PTssh *pPTssh = pMCMNode->pPTsshObj;
				pMCMNode->pPTsshObj = NULL;
				
				pthread_mutex_unlock( &pMCMNode->m_mutex);
				pthread_mutex_destroy( &pMCMNode->m_mutex);

				//Shutdown the connection
				pPTssh->disconnect();
				delete pPTssh;
			}

		if (pMCMNode->pPTsshObj)
			pthread_mutex_unlock( &pMCMNode->m_mutex);
	}

	pthread_mutex_unlock( &m_listMutex);
}
