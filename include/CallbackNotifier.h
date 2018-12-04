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


#ifndef _CALLBACKNOTIFIER
#define _CALLBACKNOTIFIER

/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"
#include "PTsshThread.h"

/*************************
* Forward declarations
*************************/


class CallbackNotifier :
public PTsshThread
{
public:
	CallbackNotifier(void);
	~CallbackNotifier(void);

	/**
	* Sets the data that the callback notifier class will use to
	* do the callback function */
	void setCallbackData(struct PTsshCallBackData *pCBD)
	{ m_pCBD = pCBD; }

	void run();

private:
	struct PTsshCallBackData 
		*m_pCBD;
};

#endif
