
PROJECT(PTSSH)

#if you don't want the full compiler output, remove the following line
SET(CMAKE_VERBOSE_MAKEFILE ON)
cmake_minimum_required(VERSION 3.7)

# Set the build type
SET(CMAKE_BUILD_TYPE Debug)

#add definitions, compiler switches, etc.
#ADD_DEFINITIONS(-Wall -O2)

SET(PTsshSources
   ${CMAKE_CURRENT_SOURCE_DIR}/src/BinaryPacket.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/CallbackNotifier.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/Channel.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/ChannelManager.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/Compress.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/CryptoStuff.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/Data.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/LinkedList.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/PTSftp.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/PTssh.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/PTsshLog.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/PTsshSocket.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/PTsshThread.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/Queue.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/SftpAttrs.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/SftpBinaryPacket.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/SftpDirHandle.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/SftpFileHandle.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/SftpHandle.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/SftpRequestMgr.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/SocketRecieve.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/SocketSend.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/TcpIpTunnelHandler.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/Transport.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/TunnelHandler.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/Utility.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/X11TunnelHandler.cpp)
   
 
 SET(PTSSH_SRC_DIR ${PTSSH_SOURCE_DIR}/src)
 message("Set PTSSH_SRC_DIR to: ${PTSSH_SRC_DIR}")
 
 SET(PTSSH_INCLUDE_DIR ${PTSSH_SOURCE_DIR}/include)
 message("Set PTSSH_INCLUDE_DIR to: ${PTSSH_INCLUDE_DIR}")
 
 
 #Link against the libs.....
#  need to link to some other libraries ? just add them here
#  TARGET_LINK_LIBRARIES(ptssh png jpeg)
#SET(LIBS pthread ssl ${LIBS})


# Check for OpenSSL
FIND_PACKAGE(OpenSSL REQUIRED)
IF(OpenSSL_FOUND)
   INCLUDE_DIRECTORIES(${OpenSSL_INCLUDE_DIR})
   SET(LIBS ${LIBS} ${OpenSSL_LIBRARIES})
ELSE(OpenSSL_FOUND)
	message(FATAL_ERROR "OpenSSL devel files not found! Perhaps you need to apt-get install libssl-dev?")
ENDIF(OpenSSL_FOUND)

# Check for ZLib
FIND_PACKAGE(ZLIB)
IF(ZLIB_FOUND)
   INCLUDE_DIRECTORIES(${ZLIB_INCLUDE_DIR})
   SET(LIBS ${LIBS} ${ZLIB_LIBRARIES})
ELSE(ZLIB_FOUND)
   message(SEND_ERROR  "Zlib devel files not found! Perhaps you need to apt-get install zlib1g-dev?")
ENDIF(ZLIB_FOUND)

#Check for pthreads
set(THREADS_PREFER_PTHREAD_FLAG ON)
FIND_PACKAGE(Threads REQUIRED)
IF(Threads_FOUND)
#   INCLUDE_DIRECTORIES(${Threads_INCLUDE_DIR})
#   SET(LIBS ${LIBS} ${Threads_LIBRARIES})
#   message("Found threads, include dir: ${Threads_INCLUDE_DIR}, lib dir: ${Threads_LIBRARIES}")
ELSE(Threads_FOUND)
	message(FATAL_ERROR "Threads devel files not found! Perhaps you need to apt-get install pthread-dev?")
ENDIF(Threads_FOUND)

# Add on pthreads and SSL libs
SET(LIBS pthread ssl ${LIBS})

message("Printing libs: ${LIBS}")

get_property(dirs DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)
foreach(dir ${dirs})
  message(STATUS "dir='${dir}'")
endforeach()

# Let CMake know about any sub-directories that might have cmake files.
# The subdirectories should also be aware of the variables that were
# created above... like ${PTsshSources}
# Library wrapper. This is the .so file that wraps our class into a
#   nice C-interfaced shared library
ADD_SUBDIRECTORY(libWrapper)

# This adds in support for building the examples sub-dir
ADD_SUBDIRECTORY(examples/automaticDirectTCPIP)
ADD_SUBDIRECTORY(examples/directTCPIP)
ADD_SUBDIRECTORY(examples/MultipleConnectionManager)
ADD_SUBDIRECTORY(examples/PTsshTesting)
ADD_SUBDIRECTORY(examples/scpReceive)
ADD_SUBDIRECTORY(examples/scpSend)
ADD_SUBDIRECTORY(examples/Sftp_usingClass)
ADD_SUBDIRECTORY(examples/SFTP_usingWrapperDLL)
ADD_SUBDIRECTORY(examples/threadedSendAndReceive)



