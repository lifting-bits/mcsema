#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(iterator BOOST_DEPENDS test tuple smart_ptr)

# These first two tests will run last, and are expected to fail
# for many less-capable compilers.

boost_test_compile_fail(interoperable_fail)
# test uses expected success, so that we catch unrelated
# compilation problems.
boost_test_run(is_convertible_fail)  
boost_test_run(zip_iterator_test)
  
# These tests should work for just about everything.
boost_test_compile(is_lvalue_iterator)
boost_test_compile(is_readable_iterator)
boost_test_compile(pointee)
  
boost_test_run(unit_tests)
boost_test_run(concept_tests)
boost_test_run(iterator_adaptor_cc)
boost_test_run(iterator_adaptor_test)
boost_test_compile(iterator_archetype_cc)
boost_test_compile_fail(iter_archetype_default_ctor)
boost_test_compile_fail(lvalue_concept_fail)
boost_test_run(transform_iterator_test)
boost_test_run(indirect_iterator_test)
boost_test_compile(indirect_iter_member_types)
boost_test_run(filter_iterator_test)
boost_test_run(iterator_facade)
boost_test_run(reverse_iterator_test)
boost_test_run(counting_iterator_test)
boost_test_run(interoperable)
boost_test_run(iterator_traits_test)
boost_test_run(permutation_iterator_test)
