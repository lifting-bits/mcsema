##########################################################################
# Boost Configuration Support                                            #
##########################################################################
# Copyright (C) 2007 Douglas Gregor <doug.gregor@gmail.com>              #
# Copyright (C) 2007 Troy Straszheim                                     #
#                                                                        #
# Distributed under the Boost Software License, Version 1.0.             #
# See accompanying file LICENSE_1_0.txt or copy at                       #
#   http://www.boost.org/LICENSE_1_0.txt                                 #
##########################################################################
# This module defines several variables that provide information about   #
# the target compiler and platform.                                      #
#                                                                        #
# Variables defined:                                                     #
#                                                                        #
#   BOOST_TOOLSET:                                                       #
#     The Boost toolset name, used by the library version mechanism to   #
#     encode the compiler and version into the name of the               #
#     library. This toolset name will correspond with Boost.Build        #
#     version 2's toolset name, including version number.                #
#                                                                        #
#   MULTI_THREADED_COMPILE_FLAGS:                                        #
#     Compilation flags when building multi-threaded programs.           #
#                                                                        #
#   MULTI_THREADED_LINK_FLAGS:                                           #
#     Linker flags when building multi-threaded programs.                #
##########################################################################
include(CheckCXXSourceCompiles)


# Toolset detection.
# Note: Known MS Visual C/C++ versions (CMake MSVC_VERSION variable),
#       as of July 2012 (see for instance:
#       http://cmake.org/cmake/help/v2.8.8/cmake.html#variable:MSVC):
#       1200 = VS 6.0; 1300 = VS 7.0; 1310 = VS 7.1;
#       1400 = VS 8.0; 1500 = VS 9.0; 1600 = VS 10.0
if (NOT BOOST_TOOLSET)
  set(BOOST_TOOLSET "unknown")
  if (MSVC60)
    set(BOOST_TOOLSET "vc6")
    set(BOOST_COMPILER "msvc")
    set(BOOST_COMPILER_VERSION "6.0")
  elseif(MSVC70)
    set(BOOST_TOOLSET "vc7")
    set(BOOST_COMPILER "msvc")
    set(BOOST_COMPILER_VERSION "7.0")
  elseif(MSVC71)
    set(BOOST_TOOLSET "vc71")
    set(BOOST_COMPILER "msvc")
    set(BOOST_COMPILER_VERSION "7.1")
  elseif(MSVC80)
    set(BOOST_TOOLSET "vc80")
    set(BOOST_COMPILER "msvc")
    set(BOOST_COMPILER_VERSION "8.0")
  elseif(MSVC90)
    set(BOOST_TOOLSET "vc90")
    set(BOOST_COMPILER "msvc")
    set(BOOST_COMPILER_VERSION "9.0")
  elseif(MSVC10)
    set(BOOST_TOOLSET "vc100")
    set(BOOST_COMPILER "msvc")
    set(BOOST_COMPILER_VERSION "10.0")
  elseif(MSVC11)
    set(BOOST_TOOLSET "vc110")
    set(BOOST_COMPILER "msvc")
    set(BOOST_COMPILER_VERSION "11.0")
  elseif(MSVC12)
    set(BOOST_TOOLSET "vc120")
    set(BOOST_COMPILER "msvc")
    set(BOOST_COMPILER_VERSION "12.0")
  elseif(MSVC14)
    set(BOOST_TOOLSET "vc140")
    set(BOOST_COMPILER "msvc")
    set(BOOST_COMPILER_VERSION "14.0")
  elseif(MSVC)
    set(BOOST_TOOLSET "vc")
    set(BOOST_COMPILER "msvc")
    set(BOOST_COMPILER_VERSION "unknown")
  elseif(BORLAND)
    set(BOOST_TOOLSET "bcb")
    set(BOOST_COMPILER "msvc")
    set(BOOST_COMPILER_VERSION "unknown")
  elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    set(BOOST_COMPILER "gcc")

    # Execute GCC with the -dumpversion option, to give us a version string
    execute_process(
      COMMAND ${CMAKE_CXX_COMPILER} "-dumpversion" 
      OUTPUT_VARIABLE GCC_VERSION_STRING)
    
    # Match only the major and minor versions of the version string
    string(REGEX MATCH "[0-9]+.[0-9]+" GCC_MAJOR_MINOR_VERSION_STRING
      "${GCC_VERSION_STRING}")

    # Match the full compiler version for the build name
    string(REGEX MATCH "[0-9]+.[0-9]+.[0-9]+" BOOST_COMPILER_VERSION
      "${GCC_VERSION_STRING}")
    
    # Strip out the period between the major and minor versions
    string(REGEX REPLACE "\\." "" BOOST_VERSIONING_GCC_VERSION
      "${GCC_MAJOR_MINOR_VERSION_STRING}")
    
    # Set the GCC versioning toolset
    set(BOOST_TOOLSET "gcc${BOOST_VERSIONING_GCC_VERSION}")
  elseif(CMAKE_CXX_COMPILER MATCHES "/icpc$" 
      OR CMAKE_CXX_COMPILER MATCHES "/icpc.exe$" 
      OR CMAKE_CXX_COMPILER MATCHES "/icl.exe$")
    set(BOOST_TOOLSET "intel")
    set(BOOST_COMPILER "intel")
    set(CMAKE_COMPILER_IS_INTEL ON)
    execute_process(
      COMMAND ${CMAKE_CXX_COMPILER} "-dumpversion"
      OUTPUT_VARIABLE INTEL_VERSION_STRING
      OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(BOOST_COMPILER_VERSION ${INTEL_VERSION_STRING})
  endif(MSVC60)
endif (NOT BOOST_TOOLSET)

boost_report_pretty("Boost compiler" BOOST_COMPILER)
boost_report_pretty("Boost toolset"  BOOST_TOOLSET)

# create cache entry
set(BOOST_PLATFORM "unknown")

# Multi-threading support
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
  set(MULTI_THREADED_COMPILE_FLAGS "-pthreads")
  set(MULTI_THREADED_LINK_LIBS rt)
  set(BOOST_PLATFORM "sunos")
elseif(CMAKE_SYSTEM_NAME STREQUAL "BeOS")
  # No threading options necessary for BeOS
  set(BOOST_PLATFORM "beos")
elseif(CMAKE_SYSTEM_NAME MATCHES ".*BSD")
  set(MULTI_THREADED_COMPILE_FLAGS "-pthread")
  set(MULTI_THREADED_LINK_LIBS pthread)
  set(BOOST_PLATFORM "bsd")
elseif(CMAKE_SYSTEM_NAME STREQUAL "DragonFly")
  # DragonFly is a FreeBSD bariant
  set(MULTI_THREADED_COMPILE_FLAGS "-pthread")
  set(BOOST_PLATFORM "dragonfly")
elseif(CMAKE_SYSTEM_NAME STREQUAL "IRIX")
  # TODO: GCC on Irix doesn't support multi-threading?
  set(BOOST_PLATFORM "irix")
elseif(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")
  # TODO: gcc on HP-UX does not support multi-threading?
  set(BOOST_PLATFORM "hpux")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  # No threading options necessary for Mac OS X
  set(BOOST_PLATFORM "macos")
elseif(UNIX)
  # Assume -pthread and -lrt on all other variants
  set(MULTI_THREADED_COMPILE_FLAGS "-pthread -D_REENTRANT")
  set(MULTI_THREADED_LINK_FLAGS "")  
  set(MULTI_THREADED_LINK_LIBS pthread rt)

  if (MINGW)
    set(BOOST_PLATFORM "mingw")
  elseif(CYGWIN)
    set(BOOST_PLATFORM "cygwin")
  elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(BOOST_PLATFORM "linux")
  else()
    set(BOOST_PLATFORM "unix")
  endif()
elseif(WIN32)
  set(BOOST_PLATFORM "windows")
else()
  set(BOOST_PLATFORM "unknown")
endif()

# create cache entry
set(BOOST_PLATFORM ${BOOST_PLATFORM} CACHE STRING "Boost platform name")

boost_report_pretty("Boost platform" BOOST_PLATFORM)

# Setup DEBUG_COMPILE_FLAGS, RELEASE_COMPILE_FLAGS, DEBUG_LINK_FLAGS and
# and RELEASE_LINK_FLAGS based on the CMake equivalents
if(CMAKE_CXX_FLAGS_DEBUG)
  if(MSVC)
    # Eliminate the /MDd flag; we'll add it back when we need it
    string(REPLACE "/MDd" "" CMAKE_CXX_FLAGS_DEBUG 
      "${CMAKE_CXX_FLAGS_DEBUG}") 
  endif(MSVC)
  set(DEBUG_COMPILE_FLAGS "${CMAKE_CXX_FLAGS_DEBUG}" CACHE STRING "Compilation flags for debug libraries")
endif(CMAKE_CXX_FLAGS_DEBUG)
if(CMAKE_CXX_FLAGS_RELEASE)
  if(MSVC)
    # Eliminate the /MD flag; we'll add it back when we need it
    string(REPLACE "/MD" "" CMAKE_CXX_FLAGS_RELEASE
      "${CMAKE_CXX_FLAGS_RELEASE}") 
  endif(MSVC)
  set(RELEASE_COMPILE_FLAGS "${CMAKE_CXX_FLAGS_RELEASE}" CACHE STRING "Compilation flags for release libraries")
endif(CMAKE_CXX_FLAGS_RELEASE)
if(CMAKE_SHARED_LINKER_FLAGS_DEBUG)
  set(DEBUG_LINK_FLAGS "${CMAKE_SHARED_LINKER_FLAGS_DEBUG}" CACHE STRING "Linker flags for debug libraries")
endif(CMAKE_SHARED_LINKER_FLAGS_DEBUG)
if(CMAKE_SHARED_LINKER_FLAGS_RELEASE)
  set(RELEASE_LINK_FLAGS "${CMAKE_SHARED_LINKER_FLAGS_RELEASE}" CACHE STRING "Link flags for release libraries")
endif(CMAKE_SHARED_LINKER_FLAGS_RELEASE)

# Set DEBUG_EXE_LINK_FLAGS, RELEASE_EXE_LINK_FLAGS
if (CMAKE_EXE_LINKER_FLAGS_DEBUG)
  set(DEBUG_EXE_LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS_DEBUG}")
endif (CMAKE_EXE_LINKER_FLAGS_DEBUG)
if (CMAKE_EXE_LINKER_FLAGS_RELEASE)
  set(RELEASE_EXE_LINK_FLAGS "${CMAKE_EXE_LINKER_FLAGS_RELEASE}")
endif (CMAKE_EXE_LINKER_FLAGS_RELEASE)

# Tweak the configuration and build types appropriately.
if(CMAKE_CONFIGURATION_TYPES)
  # Limit CMAKE_CONFIGURATION_TYPES to Debug and Release
  set(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "Semicolon-separate list of supported configuration types" FORCE)
else(CMAKE_CONFIGURATION_TYPES)
  # Build in release mode by default
#  if (NOT CMAKE_BUILD_TYPE)
#    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build, options are Release or Debug" FORCE)
#  endif (NOT CMAKE_BUILD_TYPE)
endif(CMAKE_CONFIGURATION_TYPES)

# Clear out the built-in C++ compiler and link flags for each of the 
# configurations.
set(CMAKE_CXX_FLAGS_DEBUG "" CACHE INTERNAL "Unused by Boost")
set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "" CACHE INTERNAL "Unused by Boost")
set(CMAKE_MODULE_LINKER_FLAGS_DEBUG "" CACHE INTERNAL "Unused by Boost")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "" CACHE INTERNAL "Unused by Boost")
set(CMAKE_CXX_FLAGS_RELEASE "" CACHE INTERNAL "Unused by Boost")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "" CACHE INTERNAL "Unused by Boost")
set(CMAKE_MODULE_LINKER_FLAGS_RELEASE "" CACHE INTERNAL "Unused by Boost")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "" CACHE INTERNAL "Unused by Boost")
set(CMAKE_CXX_FLAGS_MINSIZEREL "" CACHE INTERNAL "Unused by Boost")
set(CMAKE_SHARED_LINKER_FLAGS_MINSIZEREL "" CACHE INTERNAL "Unused by Boost")
set(CMAKE_MODULE_LINKER_FLAGS_MINSIZEREL "" CACHE INTERNAL "Unused by Boost")
set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "" CACHE INTERNAL "Unused by Boost")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "" CACHE INTERNAL "Unused by Boost")
set(CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO "" CACHE INTERNAL "Unused by Boost")
set(CMAKE_MODULE_LINKER_FLAGS_RELWITHDEBINFO "" CACHE INTERNAL "Unused by Boost")
set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "" CACHE INTERNAL "Unused by Boost")

# Set the build name 
set(BUILDNAME "${BOOST_COMPILER}-${BOOST_COMPILER_VERSION}-${BOOST_PLATFORM}")
boost_report_pretty("Build name" BUILDNAME)

set(BUILD_EXAMPLES "NONE" CACHE STRING "Semicolon-separated list of lowercase project names that should have their examples built, or \"ALL\"")

#set(BUILD_PROJECTS "ALL"  CACHE STRING "Semicolon-separated list of project to build, or \"ALL\"")

set(LIB_SUFFIX "" CACHE STRING "Name of suffix on 'lib' directory to which libs will be installed (e.g. add '64' here on certain 64 bit unices)")
if(LIB_SUFFIX)
  boost_report_pretty("Lib suffix" LIB_SUFFIX)
endif()

#
#  Only modify these if you're testing the cmake build itself
#
if(BOOST_CMAKE_SELFTEST)
  colormsg(HIMAG "***")
  colormsg(HIMAG "*** SELFTEST ENABLED")
  colormsg(HIMAG "***")
  set(root "${CMAKE_CURRENT_SOURCE_DIR}/tools/build/CMake/test")
  set(BOOST_CMAKE_SELFTEST_ROOT ${root})
else()
  set(root "${CMAKE_CURRENT_SOURCE_DIR}")
endif()

set(BOOST_LIBS_PARENT_DIR "${root}/libs" CACHE INTERNAL
  "Directory to glob tools from...  only change to test the build system itself")

set(BOOST_TOOLS_PARENT_DIR "${root}/tools" CACHE INTERNAL
  "Directory to glob tools from...  only change to test the build system itself")

