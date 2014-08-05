#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(spirit 
  BOOST_DEPENDS 
  test variant function_types intrusive 
  lambda assign iostreams math random dynamic_bitset fusion
  )

set( test_compile_flags "")

if(CMAKE_COMPILER_IS_GNUCC)
  set(test_compile_flags "-ftemplate-depth-300")
endif()


boost_test_run(qi_actions qi/actions.cpp COMPILE_FLAGS ${test_compile_flags} BOOST_LIB spirit COMPILE_FLAGS ${test_compile_flags} )

foreach(qi_run_test
    char
    char_class
    lit
    int
    uint
    real
    eps
    lazy
    tst
    symbols
    range_run
    no_case
    lexeme
    raw
    sequence
    alternative
    sequential_or
    permutation
    difference
    list
    optional
    kleene
    plus
    and_predicate
    not_predicate
    expect
    rule
    grammar
    match_manip
    binary
    debug
    end)
  boost_test_run(qi_${qi_run_test} qi/${qi_run_test}.cpp COMPILE_FLAGS ${test_compile_flags})
endforeach()

foreach(qi_compile_fail_test
    qi_grammar_fail
    qi_rule_fail)
  boost_test_compile_fail(${qi_compile_fail_test} qi/${qi_compiler_fail_test}.cpp 
    COMPILE_FLAGS ${test_compile_flags})
endforeach()

foreach(karma_run_test
    actions
    alternative
    binary
    case_handling
    center_alignment
    char
    delimiter
    eol
    eps
    format_manip
    grammar
    int_numerics
    kleene
    lazy
    left_alignment
    list
    lit
    optional
    pattern
    real_numerics
    right_alignment
    sequence)
  boost_test_run(karma_${karma_run_test} karma/${karma_run_test}.cpp COMPILE_FLAGS ${test_compile_flags})
endforeach()

foreach(karma_compile_fail_test
    karma_grammar_fail
    karma_rule_fail)
  boost_test_compile_fail(${karma_compile_fail_test} 
    karma/${karma_compile_fail_test}.cpp 
    COMPILE_FLAGS ${test_compile_flags})
endforeach()

# boost_test_run(support_hold_any support/hold_any.cpp COMPILE_FLAGS ${test_compile_flags})

# the multi_pass tests are not completed yet
#    [ run support/multi_pass_compile.cpp COMPILE_FLAGS ${test_compile_flags}      : : : : ]
#    [ run support/multi_pass.cpp COMPILE_FLAGS ${test_compile_flags}              : : : : ]

if(CMAKE_COMPILER_IS_INTEL)
  list(APPEND test_compile_flags "-no-vec")
endif()

foreach(lex_run_test
    lexertl1
    lexertl2
    lexertl3
    lexertl4
    lexertl5
    state_switcher_test)
  boost_test_run(lex_${lex_run_test} lex/${lex_run_test}.cpp 
    COMPILE_FLAGS ${test_compile_flags})
endforeach()



