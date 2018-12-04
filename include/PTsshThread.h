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

#ifndef _PTSSHTHREAD
#define _PTSSHTHREAD

/*************************
 * Includes
 ************************/
#include "PTsshConfig.h"

#include <pthread.h>



/*************************
 * Forward Declarations
 ************************/



/**
* This class provides a simple class that you can inherit from to easily create
* a thread complete with some handy stop/start functions. The only thing you'll
* need to do is define the run() function. The code in here runs in your
* new thread! */
class PTsshThread
{
public:
	/**
	* Creates a new PTsshThread object */
	PTsshThread(void);

	/**
	* Shutsdown and destroys the thread */
	~PTsshThread(void);

	/**
	* Inits internal data structures.
	@return Returns true if successful, false otherwise.
	*/
	int32 init();

	/**
	* Call this function when you are ready to start this thread and let it enter
	* into its event loop.
	@return Returns true if thread creation was successful
	*/
	bool startThread();

	/**
	* This will stop the thread from sending and let it exit its event loop.
	*/
	void stopThread();

	/**
	* Returns the status of this thread
	*/
	bool isRunning();

	/**
	* Puts the thread to sleep for the specified number of microseconds
	*/
	void microSecondSleep(uint32 microseconds);

	/**
	* Puts the thread to sleep until either the condition variable is triggered or
	* until the time limit elapses. Useful when you want to wait on an event, but you
	* don;t want to wait forever */
	void cond_timedwait( pthread_cond_t *pCondVar, pthread_mutex_t *pMutex, uint32 microsec);


protected:

	/**
	* This pure virtual function is expected to be defined in the inheriting class. This
	* will be the event loop of your thread.
	*/
	virtual void run() = 0;

	bool
		m_bIsRunning,		/**< Flag to check the status of this thread */
		m_bInitOk,          /**< Flag used to let us know if we can delete pthread_* objects. Only
							used when init() fails */
		m_bStopRunning;		/**< Flag used in our run() to check if we should stop running */
		

	pthread_mutex_t
		m_isRunningMutex,   /**< Mutex used to safeguard our m_bStopRunning and m_bIsRunning flags */
		m_cipherMutex;		/**< Mutex used to safeguard the cipher object. We lock
							this mutex while encrypting or signing a packet and unlock
							it as soon as we are done */

private:

	/**
	* Static function that we use to start the thread */
	static void * createThread(void *pThis);

	/**
	* This is called immediately following our threads startup. It locks the shutdown
	* semaphore so that we can correctly block our stopThread() call until the thread
	* truly stops running, and exits our run() function */
	void preRunInit();

	pthread_t
		m_thread;

	pthread_cond_t
		m_isRunning_cv,      /**< Condiition variable used to help us properly block the calling
							process on thread startup and shutdown until this thread has started
							or stopped */
		m_sleep_cv;		    /**< Condition variable used to help us sleep.  */
	pthread_mutex_t
		m_sleepMutex;		/**< Mutex used to help us sleep. We don;t really use it, but
							pthreads requires a mutex to use with the timed wait */
};

#endif
