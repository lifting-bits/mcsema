foreach(
    example
    # sexpr_output_test
    sexpr_input_test
    sexpr_error_test
)
boost_add_executable(
    ${example}
    COMPILE_FLAGS
    "-I../.."
)
endforeach(
)
