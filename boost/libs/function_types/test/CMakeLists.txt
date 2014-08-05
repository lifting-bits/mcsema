#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
# Get the boost dependencies for the tests
boost_additional_test_dependencies(function_types BOOST_DEPENDS test fusion)

boost_test_compile(is_function classification/is_function.cpp)
boost_test_compile(is_function_pointer classification/is_function_pointer.cpp)
boost_test_compile(is_function_reference classification/is_function_reference.cpp)
boost_test_compile(is_member_function_pointer classification/is_member_function_pointer.cpp)
boost_test_compile(is_member_object_pointer classification/is_member_object_pointer.cpp)
boost_test_compile(is_callable_builtin classification/is_callable_builtin.cpp)
boost_test_compile(is_nonmember_callable_builtin classification/is_nonmember_callable_builtin.cpp)
boost_test_compile(is_member_pointer classification/is_member_pointer.cpp)

boost_test_compile(is_cv_mem_func_ptr classification/is_cv_mem_func_ptr.cpp)
boost_test_compile(is_variadic classification/is_variadic.cpp)
boost_test_compile(is_cv_pointer classification/is_cv_pointer.cpp)
    # [ compile classification/is_cv_function.cpp)

# Decomposition
    
boost_test_compile(components decomposition/components.cpp)
boost_test_compile(result_type decomposition/result_type.cpp)
boost_test_compile(function_arity decomposition/function_arity.cpp)
boost_test_compile(parameter_types decomposition/parameter_types.cpp)

boost_test_compile(components_seq decomposition/components_seq.cpp)
boost_test_compile(class_type_transform decomposition/class_type_transform.cpp)

boost_test_compile_fail(result_type_fail decomposition/result_type_fail.cpp)
boost_test_compile_fail(parameter_types_fail decomposition/parameter_types_fail.cpp)
boost_test_compile_fail(function_arity_fail decomposition/function_arity_fail.cpp)

# Synthesis

boost_test_compile(function_type synthesis/function_type.cpp)
boost_test_compile(function_pointer synthesis/function_pointer.cpp)
boost_test_compile(function_reference synthesis/function_reference.cpp)
boost_test_compile(member_function_pointer synthesis/member_function_pointer.cpp)
boost_test_compile(member_object_pointer synthesis/member_object_pointer.cpp)

boost_test_compile(transformation synthesis/transformation.cpp)
boost_test_compile(mem_func_ptr_cv1 synthesis/mem_func_ptr_cv1.cpp)
boost_test_compile(mem_func_ptr_cv2 synthesis/mem_func_ptr_cv2.cpp)
boost_test_compile(mem_func_ptr_cv_ptr_to_this synthesis/mem_func_ptr_cv_ptr_to_this.cpp)
boost_test_compile(variadic_function_synthesis synthesis/variadic_function_synthesis.cpp)
    # [ compile synthesis/cv_function_synthesis.cpp)

# Reconfiguration

boost_test_compile(preprocessing_mode reconfiguration/preprocessing_mode.cpp)
boost_test_compile(partial_arity_preprocessing reconfiguration/partial_arity_preprocessing.cpp)
boost_test_compile(cc_preprocessing reconfiguration/cc_preprocessing.cpp)

# Custom calling conventions
boost_test_compile(nonmember_ccs custom_ccs/nonmember_ccs.cpp)
boost_test_compile(nonmember_ccs_exact custom_ccs/nonmember_ccs_exact.cpp)
message(STATUS "Function_Types/test/custom_ccs/member_ccs.cpp Needs love")
#boost_test_compile(member_ccs custom_ccs/member_ccs.cpp)
message(STATUS "Function_Types/test/custom_ccs/member_ccs_exact.cpp Needs love")
#boost_test_compile(member_ccs_exact custom_ccs/member_ccs_exact.cpp)


# Code from the examples
# Include the "example" directory
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/example")
boost_test_compile(interpreter_example ../example/interpreter_example.cpp)
boost_test_compile(result_of_example ../example/result_of_example.cpp)
boost_test_compile(interface_example ../example/interface_example.cpp)
message(STATUS "Function_Types/example/fast_mem_fn_example.cpp Needs love")
#boost_test_compile(fast_mem_fn_example ../example/fast_mem_fn_example.cpp)
boost_test_compile(macro_type_args_example ../example/macro_type_args_example.cpp)
