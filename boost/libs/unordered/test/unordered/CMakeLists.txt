#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
#-------------------------------------------------------------------------------
# Unordered Tests
foreach(test
    fwd_set_test
    fwd_map_test
    compile_set
    compile_map
    simple_tests
    equivalent_keys_tests
    constructor_tests
    copy_tests
    move_tests
    assign_tests
    insert_tests
    insert_stable_tests
    unnecessary_copy_tests
    erase_tests
    erase_equiv_tests
    find_tests
    at_tests
    bucket_tests
    load_factor_tests
    rehash_tests
    equality_tests
    )
  boost_test_run(${test} 
    COMPILE_FLAGS ${test_compile_flags} 
    DEPENDS boost_unit_test_framework) 
endforeach()

boost_test_run(link_test link_test_1.cpp link_test_2.cpp)

#-- run the swap test
boost_test_run(swap_tests 
                COMPILE_FLAGS ${swap_compile_flags} 
                DEPENDS boost_unit_test_framework)

