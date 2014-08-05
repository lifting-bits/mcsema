#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(conversion BOOST_DEPENDS test detail numeric)

boost_test_run(implicit_cast)
boost_test_compile_fail(implicit_cast_fail)
boost_test_run(cast_test ../cast_test.cpp)
boost_test_run(numeric_cast_test ../numeric_cast_test.cpp)
boost_test_run(
  lexical_cast_test 
  ../lexical_cast_test.cpp 
  DEPENDS boost_unit_test_framework
)


      
