#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
add_definitions(-DLIBNAME=a)

boost_add_library(a

  lib.cpp

  SHARED_COMPILE_FLAGS           "-DSHARED_OR_STATIC=SHARED"
  STATIC_COMPILE_FLAGS           "-DSHARED_OR_STATIC=STATIC"
  DEBUG_COMPILE_FLAGS            "-DDEBUG_OR_RELEASE=DEBUG"
  RELEASE_COMPILE_FLAGS          "-DDEBUG_OR_RELEASE=RELEASE"
  SINGLE_THREADED_COMPILE_FLAGS  "-DSINGLE_OR_MULTI=SINGLE_THREADED"
  MULTI_THREADED_COMPILE_FLAGS   "-DSINGLE_OR_MULTI=MULTI_THREADED"
  )

foreach(shared_or_static SHARED STATIC)
  foreach(debug_or_release DEBUG RELEASE)
    foreach(single_or_multi SINGLE_THREADED MULTI_THREADED)
  
      message("---------------------------------------------------")

      boost_add_executable(${shared_or_static}_${debug_or_release}_${single_or_multi}

	main.cpp
	
	DEPENDS boost_a

	${shared_or_static}
	${debug_or_release}
	${single_or_multi}
	)
    endforeach()    
  endforeach()    
endforeach()

