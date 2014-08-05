foreach(
    example
    complex_number
    # complex_number_adapt
    # calc2_ast_dump
    generate_code
    quick_start1
    customize_use_as_container
    # printf_style_double_format
    num_list1
    num_list2
    num_list3
    classify_char
    customize_counter
    # calc2_ast_vm
    # simple_columns_directive
    escaped_string
    reorder_struct
    actions
    complex_number_easier
    # auto_facilities
    num_matrix
    customize_embedded_container
    # reference
    mini_xml_karma
    key_value_sequence
    quoted_strings
    # calc2_ast_rpn
    # basic_facilities
)
boost_add_executable(
    ${example}
    TARGET_PREFIX
    "karma-"
)
endforeach(
)
