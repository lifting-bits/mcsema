#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(concept_check BOOST_DEPENDS utility)

# this fails but looks like it isn't the build
# boost_test_run(../stl_concept_covering)
boost_test_run(concept_check_test ../concept_check_test.cpp)
boost_test_run(class_concept_check_test ../class_concept_check_test.cpp)
boost_test_compile_fail(concept_check_fail_expected ../concept_check_fail_expected.cpp)
boost_test_compile_fail(class_concept_fail_expected ../class_concept_fail_expected.cpp)
