# # copyright John Maddock 2003
# # Distributed under the Boost Software License, Version 1.0. 
# # (See accompanying file LICENSE_1_0.txt or copy at 
# # http://www.boost.org/LICENSE_1_0.txt.
# 
# project
#     : requirements 
#       <threading>multi 
#       <link>shared:<define>BOOST_REGEX_DYN_LINK=1
#       # There are unidentified linker problems on these platforms:
#       <toolset>mipspro-7.4:<link>static
#       <toolset>sun-5.9:<link>static
#     ;
# 
# 
# rule regex-test-run ( sources + : input * : name * )
# {
#         return [ 
#            run
#              # sources
#              $(sources)
#              # dependencies
#              ../build//boost_regex
#          :  # additional args
#             $(input)
#          :  # test-files
#          :  # requirements
#             <toolset>msvc-7.1:<define>TEST_MFC=1 <toolset>msvc-7.0:<define>TEST_MFC=1
#          :  # test name
#             $(name)
#         ] ;
# }
# 
# test-suite regex-examples :



regex_test(regex_timer timer/regex_timer.cpp ARGS  ${CMAKE_SOURCE_DIR}/libs/regex/example/timer/input_script.txt )
#regex_test(regex-test-run grep/grep.cpp ../../program_options/build//boost_program_options/<link>static  -n -b ${CMAKE_SOURCE_DIR}/boost/regex.hpp ${CMAKE_SOURCE_DIR}/boost/type_traits.hpp : test_grep )
regex_test(credit_card_example snippets/credit_card_example.cpp DEPENDS boost_regex)
regex_test(mfc_example snippets/mfc_example.cpp )
regex_test(icu_example snippets/icu_example.cpp )
regex_test(partial_regex_grep snippets/partial_regex_grep.cpp ARGS  ${CMAKE_SOURCE_DIR}/libs/regex/index.htm )
regex_test(partial_regex_iterate snippets/partial_regex_iterate.cpp ARGS  ${CMAKE_SOURCE_DIR}/libs/regex/index.htm )
regex_test(partial_regex_match snippets/partial_regex_match.cpp ARGS  1234-5678-8765-4 )
regex_test(regex_grep_example_1 snippets/regex_grep_example_1.cpp ARGS  ${CMAKE_SOURCE_DIR}/boost/rational.hpp )
regex_test(regex_grep_example_2 snippets/regex_grep_example_2.cpp ARGS  ${CMAKE_SOURCE_DIR}/boost/rational.hpp )
regex_test(regex_grep_example_3 snippets/regex_grep_example_3.cpp ARGS ${CMAKE_SOURCE_DIR}/boost/rational.hpp )
regex_test(regex_grep_example_4 snippets/regex_grep_example_4.cpp ARGS ${CMAKE_SOURCE_DIR}/boost/rational.hpp )
regex_test(regex_match_example snippets/regex_match_example.cpp ARGS -auto )
regex_test(regex_merge_example snippets/regex_merge_example.cpp ARGS ${CMAKE_SOURCE_DIR}/boost/rational.hpp )
regex_test(regex_replace_example snippets/regex_replace_example.cpp ARGS ${CMAKE_SOURCE_DIR}/boost/rational.hpp )
regex_test(regex_search_example snippets/regex_search_example.cpp ARGS ${CMAKE_SOURCE_DIR}/boost/rational.hpp )
regex_test(regex_split_example_1 snippets/regex_split_example_1.cpp ARGS -auto )
regex_test(regex_split_example_2 snippets/regex_split_example_2.cpp ARGS ${CMAKE_SOURCE_DIR}/libs/regex/doc/html/index.html )
regex_test(regex_token_iterator_eg_1 snippets/regex_token_iterator_eg_1.cpp ARGS -auto )
regex_test(regex_token_iterator_eg_2 snippets/regex_token_iterator_eg_2.cpp ARGS ${CMAKE_SOURCE_DIR}/libs/regex/doc/html/index.html )
regex_test(regex_iterator_example snippets/regex_iterator_example.cpp ARGS ${CMAKE_SOURCE_DIR}/boost/rational.hpp )

#boost_test_run(run snippets/captures_example.cpp
#  ../test/captures//boost_regex_extra
#  : : :  <threading>multi <define>BOOST_REGEX_MATCH_EXTRA=1 ]

#;












