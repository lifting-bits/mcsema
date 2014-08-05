#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(optional BOOST_DEPENDS test tuple)


boost_test_run(optional_test)
boost_test_run(optional_test_tie)
boost_test_run(optional_test_ref 
  KNOWN_FAILURES "gcc-4.[0-3].[0-9]-.*")
boost_test_run(optional_test_inplace)
boost_test_run(optional_test_io)
boost_test_compile_fail(optional_test_fail1)
boost_test_compile_fail(optional_test_fail3a)
boost_test_compile_fail(optional_test_fail3b)
boost_test_compile_fail(optional_test_ref_fail1)
boost_test_compile_fail(optional_test_ref_fail3)
boost_test_compile_fail(optional_test_ref_fail4)
boost_test_compile_fail(optional_test_inplace_fail)
boost_test_compile_fail(optional_test_inplace_fail2)
