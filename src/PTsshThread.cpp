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

#include "PTsshThread.h"
#include "Utility.h"

#ifndef WIN32
#  include <unistd.h>  //Included for usleep()
#endif

#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif

///////////////////////////////////////////////////////////////////////////////
PTsshThread::PTsshThread(void):
m_bIsRunning(false),
m_bStopRunning(false),
m_bInitOk(false)
{

}

///////////////////////////////////////////////////////////////////////////////
PTsshThread::~PTsshThread(void)
{
	if ( m_bInitOk)
	{
		pthread_mutex_destroy( &m_isRunningMutex);
		pthread_mutex_destroy( &m_cipherMutex);
		pthread_mutex_destroy( &m_sleepMutex);

                pthread_cond_destroy( &m_sleep_cv);
		pthread_cond_destroy( &m_isRunning_cv);
	}
}

///////////////////////////////////////////////////////////////////////////////
int32
PTsshThread::init()
{
	if (pthread_mutex_init( &m_isRunningMutex, 0) )
		goto error; 
	if (pthread_mutex_init( &m_cipherMutex, 0) )
		goto error;
	if (pthread_mutex_init( &m_cipherMutex, 0) )
		goto error;
	if (pthread_mutex_init( &m_sleepMutex, 0) )
		goto error;
	if (pthread_cond_init( &m_sleep_cv, 0) )
		goto error;
	if (pthread_cond_init( &m_isRunning_cv, 0) )
		goto error;

	m_bInitOk = true;
	return PTSSH_SUCCESS;

error:
	pthread_mutex_destroy( &m_isRunningMutex);
	pthread_mutex_destroy( &m_cipherMutex);

	pthread_mutex_destroy( &m_sleepMutex);
	pthread_cond_destroy( &m_sleep_cv);

	pthread_cond_destroy( &m_isRunning_cv);
	return PTSSH_ERR_CouldNotAllocateMemory;
}

///////////////////////////////////////////////////////////////////////////////
bool
PTsshThread::startThread()
{
	bool bResult = false;
	if ( ! m_bInitOk)
		return false;

	int result = pthread_create( &m_thread, NULL, &PTsshThread::createThread, (void*)this );
	if ( result == 0)
	{
		//The thread should have been started, lets see if its running yet
		pthread_mutex_lock( &m_isRunningMutex);
			if ( ! m_bIsRunning)
			{
				//thread not fully running, wait for it to signal its alive
				pthread_cond_wait( &m_isRunning_cv, &m_isRunningMutex);
			}
		pthread_mutex_unlock( &m_isRunningMutex);
		bResult = true;
	}
	else
		bResult = false;

	//return the result
	return bResult;
}

///////////////////////////////////////////////////////////////////////////////
void
PTsshThread::stopThread()
{
	pthread_mutex_lock( &m_isRunningMutex);
		//Set the stop flag. The thread's run loop should exit shortly...
		m_bStopRunning = true;

		if ( m_bIsRunning)
		{
			//thread is still running, wait for it to signal its death
			pthread_cond_wait( &m_isRunning_cv, &m_isRunningMutex);
		}
	pthread_mutex_unlock( &m_isRunningMutex);
}

///////////////////////////////////////////////////////////////////////////////
bool
PTsshThread::isRunning()
{
	bool bResult;
	pthread_mutex_lock( &m_isRunningMutex);
		bResult = m_bIsRunning;
	pthread_mutex_unlock( &m_isRunningMutex);

	return bResult;
}

///////////////////////////////////////////////////////////////////////////////
void
PTsshThread::preRunInit()
{
	pthread_mutex_lock( &m_isRunningMutex);
		m_bIsRunning = true;
		
		//Signal the creator thread that we are now running
		pthread_cond_signal( &m_isRunning_cv);
	pthread_mutex_unlock( &m_isRunningMutex);
	
	this->run();

	pthread_mutex_lock( &m_isRunningMutex);
		m_bIsRunning = false;
		
		//Signal any thread waiting on us to die that we are dead
		pthread_cond_signal( &m_isRunning_cv);
	pthread_mutex_unlock( &m_isRunningMutex);
}

///////////////////////////////////////////////////////////////////////////////
void *
PTsshThread::createThread(void *pThis)
{
	//This is the beginning of the start of our new thread
	//Kick off our classes preRunInit() which will kick off our run()
	((PTsshThread*) pThis)->preRunInit();

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
void
PTsshThread::microSecondSleep(uint32 microseconds)
{
//#ifdef WIN32
	struct timespec 
		futureTime;

	//Get the absolute time a few usec in the future
	getAbsoluteTime(microseconds, futureTime);

	/* We will never signal this condition varible. We merely use this as a method to do a
	 * fine-grained sleep. Unix has usleep, but Windows....ug! */
	pthread_mutex_lock( &m_sleepMutex);
	pthread_cond_timedwait(
		&m_sleep_cv,
		&m_sleepMutex,
		(const timespec*) &futureTime);

	pthread_mutex_unlock( &m_sleepMutex);
//#else
//	//Use the naitive Unix/Linux sleep
//	usleep( (long)microseconds);
//#endif
}

///////////////////////////////////////////////////////////////////////////////
void
PTsshThread::cond_timedwait( pthread_cond_t *pCondVar, pthread_mutex_t *pMutex, uint32 microsec)
{
	struct timespec 
		futureTime;

	//Get the absolute time a few usec in the future
	getAbsoluteTime(microsec, futureTime);

	/* We will never signal this condition varible. We merely use this as a method to do a
	 * fine-grained sleep. Unix has usleep, but Windows....ug! */
	pthread_mutex_lock( pMutex);
	pthread_cond_timedwait(
		pCondVar,
		pMutex,
		(const timespec*) &futureTime);

	pthread_mutex_unlock( pMutex);
}