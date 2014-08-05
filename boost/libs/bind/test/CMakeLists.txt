#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(bind BOOST_DEPENDS test)

SET(tests 
    bind_test
    bind_dm_test
    bind_eq_test
    bind_const_test
    bind_cv_test
    bind_stateful_test
    bind_dm2_test
    bind_not_test
    bind_rel_test
    bind_function_test
    bind_lookup_problem_test
    bind_rv_sp_test
    bind_dm3_test
    bind_visit_test 
    bind_placeholder_test
    bind_rvalue_test
    bind_and_or_test
    mem_fn_test 
    mem_fn_void_test 
    mem_fn_derived_test 
    mem_fn_eq_test 
    mem_fn_dm_test 
    mem_fn_rv_test 
    ref_fn_test
    bind_fnobj2_test
    bind_fn2_test
    bind_mf2_test
    bind_eq2_test
    mem_fn_ref_test
    bind_ref_test
    bind_eq3_test
    )
FOREACH(test ${tests})
  boost_test_run(${test})
ENDFOREACH(test ${tests})

boost_test_compile(bind_unary_addr)

