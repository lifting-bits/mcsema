#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
#TODO: Deal with these on OSF
#    <toolset>hp_cxx,<os>OSF:<cflags>"-fprm d"
 #   <toolset>gcc,<os>OSF:<cflags>-mfp-rounding-mode=d

#-------------------------------------------------------------------------
#-- Needed include directories for the tests
boost_additional_test_dependencies(numeric BOOST_DEPENDS test)
#-------------------------------------------------------------------------

boost_test_compile(integer)

boost_test_run(add)
boost_test_run(det)
boost_test_run(fmod)
message(STATUS "numeric/interval/test/mul needs love")
#boost_test_run(mul)
message(STATUS "numeric/interval/test/overflow needs love")
#boost_test_run(overflow)
boost_test_run(pi)
boost_test_run(pow)

boost_test_run(cmp DEPENDS boost_test_exec_monitor)
boost_test_run(cmp_exn DEPENDS boost_test_exec_monitor)
boost_test_run(cmp_exp DEPENDS boost_test_exec_monitor)
boost_test_run(cmp_lex DEPENDS boost_test_exec_monitor)
boost_test_run(cmp_set DEPENDS boost_test_exec_monitor)
boost_test_run(cmp_tribool DEPENDS boost_test_exec_monitor)
boost_test_run(test_float DEPENDS boost_test_exec_monitor)
