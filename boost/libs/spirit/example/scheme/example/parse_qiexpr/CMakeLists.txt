boost_add_executable(
    parse_qi_test
    parse_qi_test.cpp
    generate_sexpr_to_ostream.cpp
    parse_qiexpr.cpp
    COMPILE_FLAGS
    "-I../.."
)
