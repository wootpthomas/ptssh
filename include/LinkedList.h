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


#ifndef _LINKEDLIST
#define _LINKEDLIST

/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"  //Used for dataTypes


/**
* This class provides a quick implementation of a linked list. The data
* that it stores is only pointers.
* This class is implmented as a singly linked-list.
*/
class LinkedList
{
public:
	struct Node{
		void
			*m_pData;

		Node
			*m_pNext;

		Node(void *pData){
			m_pData = pData;
			m_pNext = 0;
		}

		Node(){
			m_pData = 0;
			m_pNext = 0;
		}
	};


	/**
	* Constructor
	*/
	LinkedList();
	
	~LinkedList();

	/**
	* Returns the number of items in the list 
	*/
	uint32 size() { return m_size; }

	/* Allows us to look at the data at the specified index. This does
	* not remove the data from the queue */
	void * peek(uint32 index);

	/**
	* Removes the item at the beginning of the list. This is extremely
	* quick, does not require iteration over the list.
	*/
	void * removeFirst() { return remove(0); }

	///**
	//* Removes an item at the end of the list
	//*/
	//void * removeLast();

	/**
	* Allows us to remove an item out of the queue at the 
	* specified index. 
	*/
	void * remove(uint32 index);

	/**
	* Removes a node that has a matching data pointer
	*/
	bool removeNodeWithMatchingData( void *pFindMe);

	///**
	//* Lets us insert an item at the front of the list
	//*/
	//bool insertAtFront(void *pData);

	/**
	* Lets us insert an item at the end of the list. This is extremely
	* quick and does not require iteration over the list
	*/
	bool insertAtEnd(void *pInsertMe);

	/* Lets us insert an item in the list before the specified index.
	 * For example, insert(0, item) inserts the item at the head of the
	 * list, insert(1, item) inserts the item as 2nd in the list, etc.
	 */
	bool insert( uint32 index, void *pInsertMe);

	/**
	* This is ONLY to be use for iterating through the nodes to find and
	* use a node's data. Do NOT use this to remove or add nodes!
	*/
	Node * getFirstNode() { return pHead->m_pNext; }

	/**
	* Used to help us iterate through the linked list. Each call to this
	* function will return a pointer to the next node in the list. When
	* we reach the end of the list, we wrap back to the beginning. If no nodes
	* are in the list, or we hit the end of the list we return NULL. Calling
	* getNextNode again will then wrap to the beginning of the list
	*/
	Node * getNextNode();

protected:
	struct Node
		*pHead,
		*pTail,
		*m_pNNIter, /**< Next Node Iterator. Helps us iterate through the nodes.
					see getNextNode() */
		speed;		/** Provided so that we can do quick inserts and removes 
					from the linked list */

	uint32
		m_size;
};

#endif
