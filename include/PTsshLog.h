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



#ifndef PTSSHLOG_H
#define PTSSHLOG_H

#include <stdarg.h>
#include <stdio.h>

#include "PTsshConfig.h"
 
#ifdef PTSSH_ENABLE_LOGGING
#define PTLOG(x) PTsshLog x
#else
#define PTLOG(x)
#endif


/**
* Sets the default print function to vprintf 
*/
extern int (*g_printFunc)(const char *, va_list);

//Current log level
extern PTSSH_LogLevel g_logLevel;

/**
* This looks at the current log level and determines if the message should be
* printed or not. If it should then it is passed to the proper print function
*/
int PTsshLog(PTSSH_LogLevel logLevel, const char * format, ...);

#endif
