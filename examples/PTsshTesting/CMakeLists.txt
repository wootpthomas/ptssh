 #
# CMakeList for building the PTsshTesting example. This example
# uses the PTssh class directly


#if you don't want the full compiler output, remove the following line
SET(CMAKE_VERBOSE_MAKEFILE ON)
cmake_minimum_required(VERSION 2.6)

# Set the build type
SET(CMAKE_BUILD_TYPE Debug)

# include the parent directories, it has a few *.h files that we need
INCLUDE_DIRECTORIES( ${PTSSH_INCLUDE_DIR})



# Specify our executable an executable file using main.cpp
ADD_EXECUTABLE(ptsshTesting main.cpp ${PTsshSources})

Target_LINK_LIBRARIES(ptsshTesting ${LIBS})
