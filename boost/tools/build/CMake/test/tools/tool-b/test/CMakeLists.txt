#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#

foreach(shared_or_static SHARED STATIC)
  foreach(debug_or_release DEBUG RELEASE)
    foreach(single_or_multi SINGLE_THREADED MULTI_THREADED)
  
      set(testname ${shared_or_static}-${debug_or_release}-${single_or_multi})
      add_test(b-${testname} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/b-${testname})
      set_tests_properties(b-${testname}
	PROPERTIES
	PASS_REGULAR_EXPRESSION "${testname}")

    endforeach()    
  endforeach()    
endforeach()

