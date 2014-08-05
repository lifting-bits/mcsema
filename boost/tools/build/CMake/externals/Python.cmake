# Copyright (C) Troy Straszheim
#
# Distributed under the Boost Software License, Version 1.0. 
# See accompanying file LICENSE_1_0.txt or copy at 
#   http://www.boost.org/LICENSE_1_0.txt 
#


#
#  Python interpreter
#
set(ENV_PYTHON_EXECUTABLE $ENV{PYTHON_EXECUTABLE})

if ((NOT PYTHONINTERP_FOUND) AND ENV_PYTHON_EXECUTABLE)
  colormsg(YELLOW "Testing PYTHON_EXECUTABLE from environment")
  find_program(PYTHON_EXECUTABLE ${ENV_PYTHON_EXECUTABLE})
  if (NOT PYTHON_EXECUTABLE)
    message(FATAL_ERROR "Environment supplied PYTHON_EXECUTABLE=${ENV_PYTHON_EXECUTABLE} but this file does not exist or is not a program.")
  endif()
  set(PYTHONINTERP_FOUND TRUE 
    CACHE BOOL "Python interpreter found")
  set(PYTHON_EXECUTABLE 
    ${ENV_PYTHON_EXECUTABLE} CACHE FILEPATH "Python interpreter found")
  message(STATUS "Ok, using ${PYTHON_EXECUTABLE}")
else()
  set(PythonInterp_FIND_QUIETLY TRUE)
  find_package(PythonInterp)
endif()

#
#  Python libs
#
set(ENV_PYTHON_LIBRARIES $ENV{PYTHON_LIBRARIES})

if ((NOT PYTHON_LIBRARIES) AND ENV_PYTHON_LIBRARIES)
  colormsg(YELLOW "Testing PYTHON_LIBRARIES from environment")
  get_filename_component(pythonlib_searchpath ${ENV_PYTHON_LIBRARIES} PATH)
  get_filename_component(pythonlib_filename   ${ENV_PYTHON_LIBRARIES} NAME)
  find_library(PYTHON_LIBRARIES ${pythonlib_filename} 
    PATHS ${pythonlib_searchpath}
    NO_DEFAULT_PATH)

  if (NOT PYTHON_LIBRARIES)
    message(FATAL_ERROR "Environment supplied PYTHON_LIBRARIES=${ENV_PYTHON_LIBRARIES} but that isn't a library.")
  endif()
  message(STATUS "Ok, using ${PYTHON_LIBRARIES}.")
endif()

set(ENV_PYTHON_DEBUG_LIBRARIES $ENV{PYTHON_DEBUG_LIBRARIES})
if ((NOT PYTHON_DEBUG_LIBRARIES) AND ENV_PYTHON_DEBUG_LIBRARIES)
  #
  #  Python debug libraries
  #
  if(ENV_PYTHON_DEBUG_LIBRARIES)
    colormsg(YELLOW "Testing PYTHON_DEBUG_LIBRARIES from environment")
    get_filename_component(pythonlib_searchpath 
      ${ENV_PYTHON_DEBUG_LIBRARIES} PATH)
    get_filename_component(pythonlib_filename   
      ${ENV_PYTHON_DEBUG_LIBRARIES} NAME)
    find_library(PYTHON_DEBUG_LIBRARIES ${pythonlib_filename} 
      PATHS ${pythonlib_searchpath}
      NO_DEFAULT_PATH)

    if (NOT PYTHON_DEBUG_LIBRARIES)
      message(FATAL_ERROR "Environment supplied PYTHON_DEBUG_LIBRARIES=${ENV_PYTHON_DEBUG_LIBRARIES} but it isn't a library.")
    endif()
    message(STATUS "Ok, using ${PYTHON_DEBUG_LIBRARIES}")
  else()
    message(STATUS "Skipping optional PYTHON_DEBUG_LIBRARIES:  not set.")
  endif()
elseif(NOT PYTHON_DEBUG_LIBRARIES)
  set(PYTHON_DEBUG_LIBRARIES PYTHON_DEBUG_LIBRARIES-NOTFOUND 
    CACHE FILEPATH "Python debug library path")
endif()

#
#  Python includes
#
set(ENV_PYTHON_INCLUDE_PATH $ENV{PYTHON_INCLUDE_PATH})
if((NOT PYTHON_INCLUDE_PATH) AND ENV_PYTHON_INCLUDE_PATH)
  if(ENV_PYTHON_INCLUDE_PATH)
    colormsg(YELLOW "Testing PYTHON_INCLUDE_PATH from environment")
    find_path(PYTHON_INCLUDE_PATH
      Python.h
      PATHS ${ENV_PYTHON_INCLUDE_PATH}
      NO_DEFAULT_PATH)

    if(PYTHON_INCLUDE_PATH)
      set(PYTHON_INCLUDE_PATH ${ENV_PYTHON_INCLUDE_PATH})
      message(STATUS "Ok, using ${PYTHON_INCLUDE_PATH}")
    else()
      message(FATAL_ERROR "Environment supplied PYTHON_INCLUDE_PATH=${ENV_PYTHON_INCLUDE_PATH} but this directory does not contain file Python.h")
    endif()
  endif()
endif()

if (PYTHON_INCLUDE_PATH AND PYTHON_LIBRARIES)
  set(PYTHONLIBS_FOUND TRUE CACHE BOOL "Python libraries found, don't redetect at configure time")

  # Determine extra libraries we need to link against to build Python
  # extension modules.
  if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")

    set(PYTHON_LIBRARIES ${PYTHON_LIBRARIES} "dl")

    if(CMAKE_COMPILER_IS_GNUCXX)
      set(PYTHON_LIBRARIES ${PYTHON_LIBRARIES} "rt")
    endif(CMAKE_COMPILER_IS_GNUCXX)

  elseif(CMAKE_SYSTEM_NAME MATCHES ".*BSD")

    set(PYTHON_LIBRARIES ${PYTHON_LIBRARIES} "pthread")

  elseif(CMAKE_SYSTEM_NAME STREQUAL "DragonFly")

    # DragonFly is a variant of FreeBSD
    set(PYTHON_LIBRARIES ${PYTHON_LIBRARIES} "pthread")

  elseif(CMAKE_SYSTEM_NAME STREQUAL "OSF")

    set(PYTHON_LIBRARIES ${PYTHON_LIBRARIES} "pthread" "dl")

    if(CMAKE_COMPILER_IS_GNUCXX)
      set(PYTHON_LIBRARIES ${PYTHON_LIBRARIES} "rt")
    endif(CMAKE_COMPILER_IS_GNUCXX)    

  elseif(CMAKE_SYSTEM_NAME STREQUAL "QNX")

    # No options necessary for QNX

  elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")

    # No options necessary for Mac OS X

  elseif(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")

    set(PYTHON_LIBRARIES ${PYTHON_LIBRARIES} "rt")

  elseif(UNIX)

    # Assume -pthread and -ldl on all other variants
    set(PYTHON_LIBRARIES ${PYTHON_LIBRARIES} "pthread" "dl")
    if(CMAKE_COMPILER_IS_GNUCXX)
      set(PYTHON_LIBRARIES ${PYTHON_LIBRARIES} "util")
    endif(CMAKE_COMPILER_IS_GNUCXX)    

  endif(CMAKE_SYSTEM_NAME STREQUAL "SunOS")


elseif(NOT PYTHONLIBS_FOUND)
  set(PythonLibs_FIND_QUIETLY TRUE)
  find_package(PythonLibs)
endif()

if(PYTHONINTERP_FOUND AND PYTHONLIBS_FOUND)
  set(PYTHON_FOUND TRUE)
else()
  set(PYTHON_FOUND FALSE)
endif()

boost_external_report(Python INCLUDE_PATH EXECUTABLE LIBRARIES DEBUG_LIBRARIES)
