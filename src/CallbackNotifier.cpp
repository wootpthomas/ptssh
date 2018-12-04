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


#include "CallbackNotifier.h"
#include "PTsshLog.h"
#include <stdio.h>

///////////////////////////////////////////////////////////////////////////////
CallbackNotifier::CallbackNotifier(void)
{
}

///////////////////////////////////////////////////////////////////////////////
CallbackNotifier::~CallbackNotifier(void)
{
	delete m_pCBD;
	delete this;   //Commit Suicide
}

///////////////////////////////////////////////////////////////////////////////
void
CallbackNotifier::run()
{
	PTLOG((LL_info, "Callback called!\n"));
	if ( m_pCBD->pCallBackFunc)
	{
		//Run the callback function!
		(*(m_pCBD->pCallBackFunc))(m_pCBD);
	}

	//Commit suicide
	this->~CallbackNotifier();
}

///////////////////////////////////////////////////////////////////////////////
