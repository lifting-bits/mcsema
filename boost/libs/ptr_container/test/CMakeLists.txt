#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(ptr_container BOOST_DEPENDS test assign numeric)

boost_test_run(ptr_inserter DEPENDS boost_unit_test_framework)
boost_test_run(ptr_vector DEPENDS boost_unit_test_framework)
boost_test_run(ptr_list DEPENDS boost_unit_test_framework)
boost_test_run(ptr_deque DEPENDS boost_unit_test_framework)
boost_test_run(ptr_set DEPENDS boost_unit_test_framework)  
boost_test_run(ptr_map DEPENDS boost_unit_test_framework)
boost_test_run(ptr_map_adapter DEPENDS boost_unit_test_framework)
boost_test_run(ptr_array DEPENDS boost_unit_test_framework)
boost_test_run(tree_test DEPENDS boost_unit_test_framework)   
boost_test_run(incomplete_type_test DEPENDS boost_unit_test_framework)
boost_test_run(view_example)
boost_test_run(iterator_test DEPENDS boost_unit_test_framework)
boost_test_run(tut1)   
boost_test_run(indirect_fun DEPENDS boost_unit_test_framework)
boost_test_run(serialization DEPENDS boost_unit_test_framework boost_serialization)
boost_test_run(no_exceptions DEPENDS boost_unit_test_framework)

boost_test_run(ptr_unordered_set DEPENDS boost_unit_test_framework)
boost_test_run(ptr_unordered_map DEPENDS boost_unit_test_framework)
boost_test_run(ptr_circular_buffer DEPENDS boost_unit_test_framework)
