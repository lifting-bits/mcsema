#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(multi_index BOOST_DEPENDS test)


boost_test_run(test_basic test_basic.cpp            test_basic_main.cpp)
boost_test_run(test_capacity test_capacity.cpp         test_capacity_main.cpp)
boost_test_run(test_comparison test_comparison.cpp       test_comparison_main.cpp)
boost_test_run(test_composite_key test_composite_key.cpp    test_composite_key_main.cpp)
boost_test_run(test_conv_iterators test_conv_iterators.cpp   test_conv_iterators_main.cpp)
boost_test_run(test_copy_assignment test_copy_assignment.cpp  test_copy_assignment_main.cpp)
boost_test_run(test_hash_ops test_hash_ops.cpp         test_hash_ops_main.cpp)
boost_test_run(test_iterators test_iterators.cpp        test_iterators_main.cpp)
boost_test_run(test_key_extractors test_key_extractors.cpp   test_key_extractors_main.cpp)
boost_test_run(test_list_ops  test_list_ops.cpp         test_list_ops_main.cpp)
boost_test_run(test_modifiers test_modifiers.cpp        test_modifiers_main.cpp)
boost_test_run(test_mpl_ops test_mpl_ops.cpp          test_mpl_ops_main.cpp)
boost_test_run(test_observers test_observers.cpp        test_observers_main.cpp)    
boost_test_run(test_projection test_projection.cpp       test_projection_main.cpp)
boost_test_run(test_range test_range.cpp            test_range_main.cpp)
boost_test_run(test_rearrange test_rearrange.cpp        test_rearrange_main.cpp)
boost_test_run(test_safe_mode test_safe_mode.cpp        test_safe_mode_main.cpp)
boost_test_run(test_serialization
  test_serialization.cpp    test_serialization1.cpp
  test_serialization2.cpp   test_serialization3.cpp
  test_serialization_main.cpp
  DEPENDS boost_serialization)
boost_test_run(test_set_ops test_set_ops.cpp          test_set_ops_main.cpp)
boost_test_run(test_special_set_ops test_special_set_ops.cpp  test_special_set_ops_main.cpp)
boost_test_run(test_update test_update.cpp           test_update_main.cpp)
