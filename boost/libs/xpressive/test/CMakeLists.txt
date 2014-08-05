#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
#  : requirements
#        <toolset>intel:<debug-symbols>off
#       <toolset>msvc,<stdlib>stlport:<define>_STLP_EXPOSE_GLOBALS_IMPLEMENTATION

#         [ linkp multiple_defs1.cpp multiple_defs2.cpp : : multiple_defs ]

# TODO: Fix these
# boost_test_fail("multipledefs")
# boost_test_fail("msvc-stlport")
boost_additional_test_dependencies(xpressive BOOST_DEPENDS test intrusive numeric range typeof function_types)

if (NOT ${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  FILE(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/libs/date_time/data")
  execute_process(COMMAND cmake -E copy "${CMAKE_SOURCE_DIR}/libs/xpressive/test/regress.txt" "${CMAKE_CURRENT_BINARY_DIR}")
endif (NOT ${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})

SET(runtests 
  regress
  c_traits
  test1
  test2
  test3
  test4
  test5
  test6
  test7
  test8
  test9
  test10
  test11
  test1u
  test2u
  test3u
  test4u
  test5u
  test6u
  test7u
  test8u
  test9u
  test10u
  test11u
  misc1
  misc2
  test_format
  test_cycles
  test_non_char
  test_static
  test_actions
  test_assert
  test_symbols
  test_dynamic
  test_dynamic_grammar
  test_skip
  )

foreach(runtest ${runtests})
  boost_test_run(${runtest} DEPENDS boost_unit_test_framework )
endforeach(runtest ${runtests})

boost_test_link(multiple_defs multiple_defs1.cpp multiple_defs2.cpp)

set(compiletests
  test_basic_regex
  test_match_results
  test_regex_algorithms
  test_regex_compiler
  test_regex_constants
  test_regex_error
  test_regex_iterator
  test_regex_primitives
  test_regex_token_iterator
  test_regex_traits 
  test_sub_match
  )

foreach(compiletest ${compiletests})
  boost_test_compile(${compiletest})
endforeach(compiletest ${compiletests})
