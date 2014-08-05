#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(units BOOST_DEPENDS test)

set(COMPILE_TESTS 
  test_predicates
  test_negative_denominator
  test_dimensionless_ice1
  test_dimensionless_ice2
  test_mixed_value_types
  test_complicated_system
  test_reduce_unit
  test_unscale
  test_constants
  )

foreach(C ${COMPILE_TESTS})
  boost_test_compile(${C})
endforeach(C ${COMPILE_TESTS})

set(RUN_TESTS
  test_dimensionless_quantity
  test_implicit_conversion
  test_quantity
  test_unit
  test_base_dimension
  test_absolute
  test_default_conversion
  test_cmath
  test_limits
  test_custom_unit
  test_scaled_conversion
  test_lambda
  )

foreach(R ${RUN_TESTS})
  boost_test_run(${R})
endforeach(R ${RUN_TESTS})

set(RUN_TESTS_WITH_DEPS
  test_conversion
  test_scaled_unit
  test_output
  test_trig
)

foreach(RD ${RUN_TESTS_WITH_DEPS})
  boost_test_run(${RD} DEPENDS boost_unit_test_framework)
endforeach(RD ${RUN_TESTS_WITH_DEPS})

set(COMPILE_FAIL_TESTS
  fail_implicit_conversion
  fail_quantity_construct
  fail_quantity_assign
  fail_quantity_add
  fail_quantity_subtract
  fail_quantity_add_assign
  fail_quantity_sub_assign
  fail_quantity_scalar_add
  fail_quantity_scalar_sub
  fail_quantity_unit_add
  fail_quantity_unit_subtract
  fail_scalar_quantity_add
  fail_scalar_quantity_sub
  fail_unit_quantity_add
  fail_unit_quantity_subtract
  fail_adl_detail
  fail_heterogeneous_unit
  fail_base_dimension
  fail_add_temperature
  fail_quantity_non_unit
  )

foreach(F ${COMPILE_FAIL_TESTS})
  boost_test_compile_fail(${F})
endforeach(F ${COMPILE_FAIL_TESTS})
