#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(unordered BOOST_DEPENDS test)

# GCC Compilers
IF(CMAKE_COMPILER_IS_GNUCC)
  SET(test_compile_flags "-Wsign-promo -Wunused-parameter")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

# Intel Compiler flags
IF( ${CMAKE_CXX_COMPILER} MATCHES "icpc" )
    SET(test_compile_flags "${test_compile_flags} -strict_ansi -cxxlib-icc")  
ENDIF( ${CMAKE_CXX_COMPILER} MATCHES "icpc" )

set (swap_compile_flags "${test_compile_flags} -DBOOST_UNORDERED_SWAP_METHOD=2")



add_subdirectory(exception)
add_subdirectory(unordered)