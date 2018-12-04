


#include "MultipleConnectionMgr.h"
#include "PTssh.h"
#include <pthread.h>
#include <stdio.h>


#define ERROR_CouldNotAllocateMemory       -1;

#define THREAD_NUMBER 8

const char
	*g_pUsername = "<username>",
	*g_pPassword = "<password>",
	*g_pHostAddress = "192.168.1.50";
uint16
	g_remotePort = 22;


MCM *g_pMCM = 0;
PTssh *pPTssh[THREAD_NUMBER] = { 0 };

typedef struct{
	int32 threadNum;
	PTssh *pPTssh;
	AuthObj *pAuthObj;
} ThreadData;

static void * connectThreadFunc(void * pData)
{
	ThreadData *pTD = (ThreadData *)pData;
	int32 result = g_pMCM->getConnection( &pTD->pPTssh, pTD->pAuthObj);
	if ( result == PTSSH_SUCCESS)
	{
		uint32 
			channelNum = -1,
			result;
		printf("Thread %d, got connection 0x%p\n", pTD->threadNum, pTD->pPTssh);

		result = pTD->pPTssh->createChannel_session( channelNum);
		if ( result == PTSSH_SUCCESS)
		{
			printf("Thread %d, is using channel %d\n", pTD->threadNum, channelNum);
			result = pTD->pPTssh->closeChannel( channelNum);
			if ( result == PTSSH_SUCCESS)
				printf("Thread %d, closed channel %d\n", pTD->threadNum, channelNum);
		}
		
	}

	return NULL;
}

static void * disconnectThreadFunc(void * pData)
{
	ThreadData *pTD = (ThreadData *)pData;

	printf("Thread %d, returned connection 0x%p\n", pTD->threadNum, pTD->pPTssh);
	g_pMCM->returnConnection(pTD->pPTssh);

	return NULL;
}

int main()
{
	pthread_t
		connectThreads[THREAD_NUMBER],
		disconnectThreads[THREAD_NUMBER];
	pthread_attr_t 
		attr;
	ThreadData
		TD[THREAD_NUMBER];

	g_pMCM = new MCM();
	if ( ! g_pMCM)
		return ERROR_CouldNotAllocateMemory;
	if ( g_pMCM->init() != PTSSH_SUCCESS)
	{
		delete g_pMCM;
		return ERROR_CouldNotAllocateMemory;
	}

	//Let's create a new authentication object
	AuthObj authObj(g_pUsername, g_pHostAddress, g_remotePort);
	authObj.pPassword = (char*)g_pPassword;

   /* Initialize and set thread detached attribute */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	for (uint32 ctr = 0; ctr < THREAD_NUMBER; ctr++)
	{
		TD[ctr].pAuthObj = &authObj;
		TD[ctr].pPTssh = 0;
		TD[ctr].threadNum = ctr;

		pthread_create( &connectThreads[ctr], &attr, connectThreadFunc, (void*)&TD[ctr] );
	}

	//Wait for the threads to each get their own PTssh object
	for (int i = 0; i < THREAD_NUMBER; i++)
	{
		void *pStatus = NULL;
		int rc = pthread_join( connectThreads[i], &pStatus);
	}

	//Make all the threads give back their PTssh objects
	for (uint32 ctr = 0; ctr < THREAD_NUMBER; ctr++)
		pthread_create( &disconnectThreads[ctr], &attr, disconnectThreadFunc, (void*)&TD[ctr]);

	//Wait for the threads to each get their own PTssh object
	for (int i = 0; i < THREAD_NUMBER; i++)
	{
		void *pStatus = NULL;
		int rc = pthread_join( disconnectThreads[i], &pStatus);
	}

	//Now sleep for a bit... the MCM should disconnect the SSH server

	//Cleanup
	pthread_attr_destroy(&attr);

	return 0;
}


