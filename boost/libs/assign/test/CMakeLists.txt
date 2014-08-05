#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(assign BOOST_DEPENDS test multi_index)

SET(TESTS 
 basic
 std
 list_of
 ptr_list_of
 static_list_of
 tuple_list_of
 list_inserter
 ptr_list_inserter
 ptr_map_inserter
 list_of_workaround 
 email_example
 my_vector_example)

FOREACH(test ${TESTS})
  boost_test_run(${test} DEPENDS boost_unit_test_framework)
ENDFOREACH(test ${TESTS})

boost_test_run(multi_index_container 
  DEPENDS boost_unit_test_framework boost_serialization)
