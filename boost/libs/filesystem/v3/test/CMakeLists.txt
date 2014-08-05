#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(filesystem BOOST_DEPENDS test bind)


ADD_DEFINITIONS(-DBOOST_ALL_NO_LIB) # -DBOOST_FILESYSTEM_STATIC_LINK

SET(TESTS path_unit_test path_test
  operations_unit_test operations_test 
  fstream_test convenience_test 
  large_file_support_test deprecated_test
  simple_ls)

FOREACH(test ${TESTS})
  boost_test_run(${test}_static
    ${test}.cpp
    DEPENDS boost_filesystem STATIC
    COMPILE_FLAGS -DBOOST_FILESYSTEM_STATIC_LINK)
  boost_test_run(${test}_dynamic
    ${test}.cpp
    DEPENDS boost_filesystem SHARED
    COMPILE_FLAGS -DBOOST_FILESYSTEM_DYN_LINK)
ENDFOREACH(test ${TESTS})
