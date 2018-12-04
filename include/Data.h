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


#ifndef _DATA
#define _DATA

/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"
//#include "Utility.h"
#include "BinaryPacket.h"

/*************************
* Forward declarations
*************************/
//class BinaryPacket;


/**
* The purpose of this class is to wrap up the raw SSH binary packet format that
* we read off the socket and provide a wrapper to let the user gain access to the
* channel data, while hiding the rest of the binary packet details from them.
* It also gives us a slight speed boost. Rather than take the raw packet, allocate
* a new packet thats to hold just the data, copy that data in and finally give that
* to the user, we give them the same data packet. Much more efficient, one memory
* allocation and we work in that space and the end-developer gets that same chunk
* of memory. The "onion" that we end up with, we hide and just point to the embedded
* data they are interested in.
*/
class Data: private BinaryPacket
{
public:
	/**
	* Constructs a user-friendly Data object that encapsulates the specified
	* SSH Binary Packet. 
	*/
	Data(void);

	~Data(void);

	/**
	* Gets a pointer to the SSH Binary Packet's channel data portion.
	* Note: you can do anything that you want with the data pointed too.
	*   But don't delete the pointer, delete this class and let it handle
	*   cleanup!
	*/
	uint8 * const getDataPtr() { return BinaryPacket::getChannelData(); }

	/**
	* Gets the length of the encapsulated data that is pointed to by the pointer
	* returned in the data() call 
	*/
	uint32 dataLen();
};

#endif
