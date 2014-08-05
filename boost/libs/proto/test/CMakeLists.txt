#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(proto BOOST_DEPENDS test)

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

set (tests
    calculator
    deep_copy
    examples
    lambda
    make_expr
    matches
    proto_fusion
    proto_fusion_s
    toy_spirit
    toy_spirit2
    noinvoke
)




#-- Create an executable test for each source
foreach(test ${tests})
    boost_test_run(${test} "${test}.cpp"
                    COMPILE_FLAGS ${test_compile_flags} 
                    DEPENDS boost_unit_test_framework) 
endforeach(test ${tests})



