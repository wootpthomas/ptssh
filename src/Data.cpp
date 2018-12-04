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
#include "Utility.h"
#include "Data.h"
#include "SSH2Types.h"
#include "BinaryPacket.h"
#include "PTsshLog.h"

#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif


///////////////////////////////////////////////////////////////////////////////
Data::Data()
{

}

///////////////////////////////////////////////////////////////////////////////
Data::~Data(void)
{

}

///////////////////////////////////////////////////////////////////////////////
uint32 
Data::dataLen()
{
	uint8 *pIter = this->m_pBP + 5;
	//pIter points to the message type at beginning of payload

	//What message type is it?
	switch ( *pIter)
	{
		case SSH_MSG_CHANNEL_DATA:
			//Point to the channel SSH string
			pIter += 5;
			return PTSSH_htons32( *( (uint32*)pIter));
			break;
		case SSH_MSG_CHANNEL_EXTENDED_DATA:
			//Point to the data type
			pIter += 9;
			return PTSSH_htons32( *( (uint32*)pIter));
			break;
		default:
			PTLOG((LL_error, "Error! Didn't expect this type of data\n"));
			break;
	}

	return 0;
}


