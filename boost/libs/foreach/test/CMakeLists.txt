#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(foreach BOOST_DEPENDS test )

set(TESTS 
stl_byval
stl_byval_r
stl_byref
stl_byref_r
array_byval
array_byval_r
array_byref
array_byref_r
cstr_byval
cstr_byval_r
cstr_byref
cstr_byref_r
pair_byval
pair_byval_r
pair_byref
pair_byref_r
user_defined
call_once
rvalue_const
rvalue_const_r
rvalue_nonconst
rvalue_nonconst_r
dependent_type
misc)

foreach(test ${TESTS})
  boost_test_run(${test})
endforeach(test ${TESTS})

boost_test_compile(noncopyable)

