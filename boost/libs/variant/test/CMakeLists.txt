#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(variant BOOST_DEPENDS test)

boost_test_run(test1 test1.cpp class_a.cpp)
boost_test_run(test4 test4.cpp class_a.cpp) 
set(tests test2 test3 test5 test6 test7 test8 recursive_variant_test variant_reference_test variant_comparison_test variant_visit_test)

foreach(test ${tests})
  boost_test_run(${test})
endforeach(test ${tests})
