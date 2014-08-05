#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#

foreach(test 
    constructor_exception_tests
    copy_exception_tests
    assign_exception_tests
    insert_exception_tests
    erase_exception_tests
    rehash_exception_tests
    )
    boost_test_run(${test} 
                    COMPILE_FLAGS ${test_compile_flags} 
                    DEPENDS boost_unit_test_framework) 
endforeach(test ${unordered_tests})

#-- run the swap test
boost_test_run(swap_exception_tests 
                COMPILE_FLAGS ${swap_compile_flags} 
                DEPENDS boost_unit_test_framework)

