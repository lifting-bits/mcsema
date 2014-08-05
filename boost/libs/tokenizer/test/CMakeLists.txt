#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(tokenizer BOOST_DEPENDS test config detail iterator utility array intrusive)

boost_test_run(examples examples.cpp 
  DEPENDS boost_test_exec_monitor)
boost_test_run(simple_example_1 simple_example_1.cpp)
boost_test_run(simple_example_2 simple_example_2.cpp)
boost_test_run(simple_example_3 simple_example_3.cpp)
boost_test_run(simple_example_4 simple_example_4.cpp)
boost_test_run(simple_example_5 simple_example_5.cpp)
