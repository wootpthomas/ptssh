#
# CMakeList for building the C-interface wrapper as a shared library
# aka, a libPTssh.so


#if you don't want the full compiler output, remove the following line
SET(CMAKE_VERBOSE_MAKEFILE ON)
cmake_minimum_required(VERSION 2.6)

# Set the build type
SET(CMAKE_BUILD_TYPE Debug)

# include the parent directory, it has a few *.h files that we need
INCLUDE_DIRECTORIES( ${PTSSH_INCLUDE_DIR})




#Add the library
ADD_LIBRARY(PTsshW SHARED ${PTsshSources} ${PTSSH_SRC_DIR}/PTsshW.cpp)

Target_LINK_LIBRARIES(PTsshW ${LIBS})
