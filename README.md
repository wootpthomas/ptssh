PTssh version 0.3.0 (alpha)

PTssh: Paul Thomas's Performance Tuned SSH library with example code.

PTssh is a cross-platform, multi-threaded SSH library built from the ground up in C++ with performance in mind. I've also created a C-based library wrapper so that you can build PTssh into either a windows DLL or a *nix SO.


Windows build instructions:
--------------------------------------
Note: You can either download the dependencies in their source form and build them or you can download one of their binary installers so that you don't need to compile anything.

1) Download and install Visual Studio 2008 (express edition should work fine)
   http://www.microsoft.com/express/vc/
2) Download and install pthreads 2.80 for windows. Source and binaries are available
	http://sourceware.org/pthreads-win32/#download
3) Download OpenSSL
   a) Method 1: Build from source:
		http://www.openssl.org/
   b) Alternate method: Install binary
	    http://www.shininglightpro.com/products/Win32OpenSSL.html   -Binary installer
4) Download Zlib (Optional)
   a) Method 1: Build from source:
		http://www.zlib.net/
   b) Alternate method: Install binary using GnuWin
	    https://sourceforge.net/projects/gnuwin32/files/
5) Setup enviornment variables. The location you put pthreads, openssl and zlib in doesn't matter as long as the variable you define is correct. The Visual Studio solutions pull in the libraries and header files based off of the value in the envoirnmental variable. I use env vars so that I can quickly and easily test my code on different versions of Zlib, OpenSSL, Pthreads, etc by simply changing where one of the env vars points to and restart Visual Studio.

ZLIB=C:\devel\code\3rdParty\zlib-1.2.3 (if using zlib)
OPENSSL=C:\devel\code\3rdParty\openssl-0.9.8g
PTHREADS=C:\devel\code\3rdParty\pthreads\Pre-built.2

5) Append the newly defined variables to your PATH. Example:
PATH=%SystemRoot%\system32;%SystemRoot%;%SystemRoot%\System32\Wbem;%OPENSSL%\out32dll;%ZLIB%;%PTHREADS%\lib

You can now open up the solution file and build all projects and examples.


Linux/Unix build instructions
--------------------------------------
1) Install pthreads, zlib (optional), openssl according to your distribution.
2) extract PTssh somewhere
3) Run CMake to generate MAKE files for your platform -or- generate an IDE project: KDevelop, Eclipse, etc.
4) Run make to build the projects and examples

Note: You'll likely end up having more fun building on Linux because the CMake files I've created were really pretty basic. Hopefully the open source community can help me improve this area! 


I hope someone finds this code useful!
Paul Thomas
thomaspu@gmail.com


