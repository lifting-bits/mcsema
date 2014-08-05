#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
if (WIN32)
  set(THREAD_SOURCES win32/thread.cpp win32/tss_dll.cpp win32/tss_pe.cpp)
else (WIN32)
  set(THREAD_SOURCES pthread/thread.cpp pthread/once.cpp)
endif (WIN32)

boost_add_library(
  thread
  ${THREAD_SOURCES}
  SHARED_COMPILE_FLAGS "-DBOOST_THREAD_BUILD_DLL=1"
  STATIC_COMPILE_FLAGS "-DBOOST_THREAD_BUILD_LIB=1"
  NO_SINGLE_THREADED
  )

