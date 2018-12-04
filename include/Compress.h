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


#ifndef _COMPRESS_H
#define _COMPRESS_H


#if defined(PTSSH_ZLIB) || defined (PTSSH_ZLIB_OPENSSH)
# include <zlib.h>
# include "PTsshConfig.h"



class BinaryPacket;

class Compress
{
public:
	Compress(int compressLevel = Z_DEFAULT_COMPRESSION);
	~Compress(void);

	int32 init(bool bIsCompression);

	int32 inflate(
		uint8 *pDataIn,
		uint32 dataInSize,
		uint8 **pDataOut,
		uint32 &expandedDataLen,
		uint32 &totalDataOutBufSize);

#ifdef PTSSH_COMP_USE_COMP_TEMP_BUF
	/**
	* This is a pretty optimized deflate function. It takes a BP and deflates it
	* in place and doesn;t require any new memory allocation. Uses a temporary
	* buffer
	*/
	int32 deflate(BinaryPacket *pBP);
#else
	int32 deflate(
		uint8 *pDataIn,
		uint32 dataInSize,
		uint8 **pDataOut,
		uint32 &compressedDataLen,
		uint32 &pDataOutLen);
#endif



	//int32 compress();

private:
	void getZlibError(int status);

	z_stream 
		m_strm;

	int
		m_compressLevel;

	bool
		m_bIsInitialized;  /**< Set to true on successful init() */

	uint32
		m_compBufSize;
	uint8
		*m_pCompBuf;
};

#endif /* PTSSH_ZLIB */

#endif /* _COMPRESS_H */