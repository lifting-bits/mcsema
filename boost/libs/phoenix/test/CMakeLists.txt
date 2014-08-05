#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(phoenix BOOST_DEPENDS test)

################################################################################
#--- Compiler specific settings

# GCC
IF(CMAKE_COMPILER_IS_GNUCC)
  SET(test_compile_flags "-ftemplate-depth-1024")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

# Microsoft Visual Studio
IF (MSVC71)
      #TODO// Turn off debug symbols?
ENDIF(MSVC71)
IF (MSVC80)
      SET(test_compile_flags "-D_CRT_SECURE_NO_DEPRECATE -D_SCL_SECURE_NO_DEPRECATE")
ENDIF(MSVC80)
IF (MSVC90)
      SET(test_compile_flags "-D_SCL_SECURE_NO_DEPRECATE")
ENDIF (MSVC90)
    
# Intel 
IF( ${CMAKE_CXX_COMPILER} MATCHES "icpc" )
    #TODO// Turn off debug symbols?
ENDIF( ${CMAKE_CXX_COMPILER} MATCHES "icpc" )

set(TESTS 
algorithm
bll_compatibility
bind
boost_bind_compatibility
container
core
function
include
object
operator
regression
scope
statement
stdlib)

foreach(TEST ${TESTS})
  boost_test_run(${TEST} DEPENDS boost_unit_test_framework)
endforeach(TEST ${TESTS})

if(WIN32)
  message("Need to turn on iterator debugging")
endif(WIN32)

