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

#ifndef _X11TUNNELHANDLER
#define _X11TUNNELHANDLER

/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"
#include "TunnelHandler.h"


/*************************
* Forward declarations
*************************/


/**
* This class was designed to handle tunneling between a local socket and a
* ssh channel for the purpose of X11 tunneling.*/
class X11TunnelHandler:
	public TunnelHandler
{
public:


	X11TunnelHandler(PTssh * const pSSH, ChannelManager * const pChannelMgr);
	~X11TunnelHandler(void);


	/* This will get things setup and ready to go when dealing with X11 forwarding.
	* If this returns success, then thats it! All X11 stuff will be handled!
	*/
	int32 init(
		uint32 localChannel,
		const char *XServerIPAddress = "127.0.0.1",	
		uint16 XServerPort = 6000);

	void shutdown();


private:

	const char 
		*pXServerIPAddress;

	uint16
		m_XServerPort;

	int
		m_x11Sock;

	uint32
		m_cNum;

	struct threadData
		*m_pTD;
};

#endif
