#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_add_library(c

  lib.cpp

  )

foreach(shared_or_static SHARED STATIC)
  foreach(debug_or_release DEBUG RELEASE)
    foreach(single_or_multi SINGLE_THREADED MULTI_THREADED)
  
      boost_add_executable(${shared_or_static}_${debug_or_release}_${single_or_multi}

	main.cpp
	DEPENDS boost_c
	${shared_or_static}
	${debug_or_release}
	${single_or_multi}
	)
    endforeach()    
  endforeach()    
endforeach()



