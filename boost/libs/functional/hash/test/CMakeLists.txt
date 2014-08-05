#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
#project hash-tests
#    : requirements
#        <toolset>gcc:<define>_GLIBCXX_DEBUG
#    ;
if (GCC)
  ADD_DEFINITIONS(-D_GLIBCXX_DEBUG)
endif(GCC)

#        [ run .cpp : : : <test-info>always_show_run_output ]



#-------------------------------------------------------------------------
#-- Needed include directories for the tests
  boost_additional_test_dependencies(functional BOOST_DEPENDS test)
#-------------------------------------------------------------------------

SET(tests
hash_fwd_test_1
hash_fwd_test_2
hash_number_test
hash_pointer_test
hash_function_pointer_test
hash_float_test
hash_long_double_test
hash_string_test
hash_range_test
hash_custom_test
hash_global_namespace_test
hash_friend_test
hash_built_in_array_test
hash_value_array_test
hash_vector_test
hash_list_test
hash_deque_test
hash_set_test
hash_map_test
hash_complex_test
container_fwd_test
hash_no_ext_macro_1
hash_no_ext_macro_2
)

boost_test_run(link_test link_test.cpp link_test_2.cpp)
boost_test_run(link_ext_test link_ext_test.cpp link_no_ext_test.cpp
)
foreach(test ${tests})
  boost_test_run(${test})
endforeach(test ${tests})

boost_test_compile_fail(hash_no_ext_fail_test)

