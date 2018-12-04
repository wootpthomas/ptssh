/**************************************************************************
*   Copyright (C) 2009 by Paul Thomas
*   thomaspu@gmail.com
*
*	This file is part of Paul Thomas' SSH class, aka PTssh.
*
*    PTssh is free software: you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation, either version 3 of the License, or
*    (at your option) any later version.
*
*    PTssh is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with PTssh.  If not, see <http://www.gnu.org/licenses/>.
*************************************************************************/



#include <sys/stat.h>
#include <time.h>
#include <fstream>
#include <pthread.h>
#include <signal.h>


#if defined(WIN32) && defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
	#define _CRTDBG_MAP_ALLOC
	#include <stdlib.h>
	#include <crtdbg.h>

//http://discuss.joelonsoftware.com/default.asp?design.4.374637.18
#   define DEBUG_NEW new( _NORMAL_BLOCK, __FILE__, __LINE__ )
#   define new DEBUG_NEW
#endif


#ifdef WIN32
#   include <winsock2.h>

	//Redefine the close() function on windows so we don't break on linux
#   define close(SOCKET)				closesocket(SOCKET)
#else
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <errno.h>
#endif


#include "PTsshW.h" //Include the wrapper, we'll use the DLL



/***********************
* Modify these values !
***********************/
const char
	*pUsername = "<username>",  //Ex: paul
	*pPassword = "<password>",  //Ex: myPassword
	*pSSHAddress = "<host>", //Ex: 192.168.1.15 -or- your.domain.com
	*pDestHost = "<destination host>", //Ex: paul.homePC.localdomain
	*pSourceHost = "<source host IP address>"; //Ex: SSH servers IP, 99% of the time, 127.0.0.1 is what you want


uint16
	SSHPort = 22,          //SSH server port number
	destPort = 3389,      /*This is the port on homePC that we want to "tunnel" to. In
					       * our example, we are setting up a tunnel for windows remote
					       * desktop. So this is the windows remote desktop port number 3389 */
    sourcePort = 22,
	localSocketNum = 3388;/* This is the local socket that you use, applications connect to this
						   * port. After they successfully connect, any data they send will end
						   * up on the other side of the tunnel: homePC port 3389 */

//Global to help catch signals
bool g_bKeepRunning = true;

void shutdown(int sig);

/************************
* This little example shows how to use the PTssh library/class to create a
* direct TCP/IP "tunnel". The tunnel will let you have a local socket and
* any data that you write to that socket will get forwarded over your SSH
* connection to the destination host.
* For instance, if your home network had a Linux/Unix computer that you could
* SSH into and that SSH computer could talk to PCs behind a firewall, like
* your home computer and you wanted to be able to remotely connect to your home
* PC that can;t be directly accessed, you could setup a TCP/IP tunnel.
*
* You work PC      Home network router/firewall   Home PC
*                           ||               
*     wPC                linuxPC                   homePC
*                           ||               
* After you create the tunnel, you would have a local socket on your work PC
* that you can connect to and any data written on it goes over SSH to
* linuxPC and then that data gets forwarded to homePC. LinuxPC would act as
* a middle-man.
*
* Please note that you do not have to use a socket for tunneling. We just use a
* socket here in this example because it shows how the majority of people will 
* likely use tunneling.
***********************/
int main()
{
#ifdef WIN32
	//IF MEMORY_LEAK_DETECTION is defined, memory leaks will be printed out if found
#   if defined(_DEBUG) && defined(MEMORY_LEAK_DETECTION)
		_CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
#   endif
#endif 
	
	/***********************
	* Other variables used
	***********************/
	int 
		result;
	bool 
		bIsAuthenticated = false,
		bConnected = false;
	uint32
		cNum = -1,
		totalBytesQueued = 0;

	//Setup our signal handler to catch CTRL + C
	(void) signal(SIGTERM, shutdown);
	(void) signal(SIGINT, shutdown);

	/* Initialize the library. Make sure it returns a success code before 
	 * you continue! */
	PTssh *pSSH = ptssh_create();
	if ( pSSH && ptssh_init(pSSH, pUsername, pSSHAddress, SSHPort) != PTSSH_SUCCESS )
		return false;

	/* Now make the actual connection to the SSH server. This will create
	 * a socket and negotiate all SSH stuff. If successful, we'll then
	 * be able to authenticate. IF this fails, check the failure code
	 * for more details as to wtf is going on.
	 * The remote address can either be an IPv4 address or a fully qualified
	 * URL:
	 * 127.0.0.1
	 *   -or-
	 * woot.my.sshserver.com  */
	result = ptssh_connect(pSSH);
	if ( result < 0)
	{
		printf("Failed to connect to %s:%d PTssh error number %d\n", pSSHAddress, SSHPort, result );
		return -1;
	}

#ifdef AUTHENTICATION_TEST
	/* Let's see what authentication methods are allowed by the server. PTssh
	 * supports quite a few */
	bool 
		bAuthPassword = false,
		bAuthHost = false,
		bAuthPublicKey = false,
		bAuthKbdInt = false,
		bAuthNone = false;
	if (
		ptssh_isAuthSupported(pSSH, PTsshAuth_Password, bAuthPassword) != PTSSH_SUCCESS ||
		ptssh_isAuthSupported(pSSH, PTsshAuth_HostBased, bAuthHost) != PTSSH_SUCCESS ||
		ptssh_isAuthSupported(pSSH, PTsshAuth_PublicKey, bAuthPublicKey) != PTSSH_SUCCESS ||
		ptssh_isAuthSupported(pSSH, PTsshAuth_KeyboardInteractive, bAuthKbdInt) != PTSSH_SUCCESS ||
		ptssh_isAuthSupported(pSSH, PTsshAuth_None, bAuthNone) != PTSSH_SUCCESS )
	{
		ptssh_disconnect(pSSH);
		return -1;
	}

	if ( bAuthPassword)
		printf("Server supports authentication by password\n");
	if ( bAuthHost)
		printf("Server supports authentication by host\n");
	if ( bAuthPublicKey)
		printf("Server supports authentication by public key\n");
	if ( bAuthKbdInt)
		printf("Server supports authentication by keyboard interactive login\n");
	if ( bAuthNone)
		printf("Server supports authentication by \"none\" method\n");

#endif /* AUTHENTICATION_TEST */

	//Authenticate by password
	if ( ptssh_authByPassword(pSSH, pPassword) != PTSSH_SUCCESS)
	{
		printf("Authentication failed\n");
		ptssh_disconnect(pSSH);
		return -2;
	}

	//Tunnel using PTssh's built-in automatic tunneling
	result = ptssh_createChannel_AutomaticDirectTCPIP(
		pSSH,
		localSocketNum,
		2, //Max connections
		NULL,
		pDestHost,
		destPort,
		pSourceHost,
		sourcePort);
	if ( result == PTSSH_SUCCESS)
	{
		printf("[autoTunneling] Ready to accept connections through port %d\n", localSocketNum);
		printf("[autoTunneling] ##############################\n");
		printf("[autoTunneling] # Press CTRL + C to exit!    #\n");
		printf("[autoTunneling] ##############################\n");
		while ( g_bKeepRunning)
		{
#ifdef WIN32
			Sleep(1);
#else
			sleep(1000);
#endif
		}

		printf("Closing tunnel...\n");
		result = ptssh_closeAutomaticDirectTCPIP(pSSH, localSocketNum);
		if ( result == PTSSH_SUCCESS)
			printf("Successfully shut down tunneling for local socket %d\n", localSocketNum);
		else
			printf("Failed to shut down tunneling for local socket %d\n", localSocketNum);
	}

	//Close down our connection gracefully
	result = ptssh_disconnect(pSSH);
	if ( result != PTSSH_SUCCESS)
	{
		printf("Error shutting down!\n");
		return -4;
	}

	ptssh_destroy( &pSSH);

}

void shutdown(int sig)
{
	printf("Sig %d. Shutting down...\n", sig);
	g_bKeepRunning = false;
}
