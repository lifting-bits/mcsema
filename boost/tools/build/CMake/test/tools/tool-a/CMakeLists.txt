#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_tool_project(tool-a
  DESCRIPTION "tool-a"
  AUTHORS "author-a"
  )

foreach(shared_or_static SHARED STATIC)
  foreach(debug_or_release DEBUG RELEASE)
    foreach(single_or_multi SINGLE_THREADED MULTI_THREADED)
  
      set(typestring ${shared_or_static}-${debug_or_release}-${single_or_multi})
      boost_add_executable(tool-a-${typestring}

	main.cpp
	
	DEPENDS a

	${shared_or_static}
	${debug_or_release}
	${single_or_multi}
	)

      add_test(tool-a-${typestring} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/tool-a-${typestring})
      set_tests_properties(tool-a-${typestring}
	PROPERTIES
	PASS_REGULAR_EXPRESSION tool-a-${typestring})

    endforeach()    
  endforeach()    
endforeach()

