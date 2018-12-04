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
#include "PTsshConfig.h"
#include "LinkedList.h"
#include "PTsshLog.h"

#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif

#include <stdio.h>


///////////////////////////////////////////////////////////////////////////////
LinkedList::LinkedList():
m_size(0),
m_pNNIter(0)
{
	pHead = &speed;
	pTail = &speed;
}

///////////////////////////////////////////////////////////////////////////////
LinkedList::~LinkedList()
{
	if ( m_size) {
		PTLOG(( LL_error, "[LL] Delete was called on a non-empty list. Memory leak.\n"));
	}

	m_size = 0;
	pHead = 0;
	pTail = 0;
}

///////////////////////////////////////////////////////////////////////////////
void *
LinkedList::peek(uint32 index)
{
	void *pData = 0;
	if ( index < m_size)
	{
		struct Node *pIter = pHead->m_pNext;
		uint32 ctr = 0;
		while (ctr++ < index)
			pIter = pIter->m_pNext;

		pData = pIter->m_pData;
	}

	return pData;
}

///////////////////////////////////////////////////////////////////////////////
void *
LinkedList::remove(uint32 index)
{
	void *pData = 0;
	if ( index < m_size)
	{
		struct Node
			*pIter = pHead->m_pNext,
			*pIterPrev = pHead;
		uint32
			ctr = 0;

		while (ctr++ < index) {
			pIterPrev = pIter;
			pIter = pIter->m_pNext;
		}

		//Point to the data to return
		pData = pIter->m_pData;

		//Move our next node pointer off this object
		if ( pIter == m_pNNIter)
			getNextNode();

		//Re-route the node out of the list
		pIterPrev->m_pNext = pIter->m_pNext;

		//Does this effect the tail?
		if ( pIter == pTail)
			pTail = pIterPrev;

		//Finally delete the old node
		delete pIter;
		pIter = 0;

		m_size--;
	}

	return pData;
}

///////////////////////////////////////////////////////////////////////////////
bool
LinkedList::removeNodeWithMatchingData( void *pFindMe)
{
	if ( m_size > 0)
	{
		struct Node
			*pIter = pHead->m_pNext,
			*pIterPrev = pHead;
		uint32
			ctr = 0;

		while (pIter && pIter->m_pData != pFindMe) {
			pIterPrev = pIter;
			pIter = pIter->m_pNext;
		}

		if ( pIter && pIter->m_pData == pFindMe)
		{
			//Re-route the node out of the list
			pIterPrev->m_pNext = pIter->m_pNext;

			//Does this effect the tail?
			if ( pIter == pTail)
				pTail = pIterPrev;

			//Move our next node pointer off this object
			if ( pIter == m_pNNIter)
				getNextNode();

			delete pIter;
			m_size--;
			return true;
		}
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
bool
LinkedList::insertAtEnd(void *pInsertMe)
{
	struct Node 
		*pNewNode = new Node(pInsertMe);

	if ( ! pNewNode)
		return false;

	//Put the new node on the end of the list
	pTail->m_pNext = pNewNode;
	pTail = pNewNode;

	m_size++;

	return true;
}

///////////////////////////////////////////////////////////////////////////////
bool
LinkedList::insert( uint32 index, void *pInsertMe)
{
	struct Node 
		*pNewNode = new Node(pInsertMe);

	if ( ! pNewNode)
		return false;

	if ( index > m_size)
		index = m_size;

	if ( m_size)
	{
		struct Node
			*pIter = pHead->m_pNext,
			*pIterPrev = pHead;
		uint32 ctr = 0;

		while (ctr++ < index) {
			pIterPrev = pIter;
			pIter = pIter->m_pNext;
		}

		/* We now have pIterPrev pointing to the node that will be in front and
		 * pIter points to the node that will be in back */

		//Insert the new item
		pIterPrev->m_pNext = pNewNode;
		pNewNode->m_pNext = pIter;

		//Does this effect the tail? pIter=NULL if our new node is now on the end of the list
		if ( ! pIter)
			pTail = pNewNode;

		m_size++;
		//PTLOG(("Queue size: %d\n", m_size));
	}
	else
	{
		//Inserting into an empty list
		pTail->m_pNext = pNewNode;
		pTail = pNewNode;

		//Point our iterator to the new node
		m_pNNIter = pTail;

		++m_size;
	}

	return true;
}

///////////////////////////////////////////////////////////////////////////////
LinkedList::Node *
LinkedList::getNextNode()
{
	//Get a pointer to the node we will return
	LinkedList::Node *pNode = m_pNNIter;

	//Move our pointer to the next node. Wrap if we hit the end of the list
	//This sets us up for the next call to getNextNode
	if ( m_pNNIter)
		m_pNNIter = m_pNNIter->m_pNext;
	else
		m_pNNIter = pHead->m_pNext;

	return pNode;
}
