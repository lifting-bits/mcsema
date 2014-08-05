#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(regex BOOST_DEPENDS test)

set(R_SOURCES
  regress/basic_tests.cpp
  regress/main.cpp
  regress/test_alt.cpp
  regress/test_anchors.cpp
  regress/test_asserts.cpp
  regress/test_backrefs.cpp
  regress/test_deprecated.cpp
  regress/test_emacs.cpp
  regress/test_escapes.cpp
  regress/test_grep.cpp
  regress/test_locale.cpp
  regress/test_mfc.cpp
  regress/test_non_greedy_repeats.cpp
  regress/test_perl_ex.cpp
  regress/test_replace.cpp
  regress/test_sets.cpp
  regress/test_simple_repeats.cpp
  regress/test_tricky_cases.cpp
  regress/test_icu.cpp
  regress/test_unicode.cpp
  regress/test_overloads.cpp
  regress/test_operators.cpp
  )

if (NOT ICU_FOUND)
  # static tests eliminiated if ICU is found
  boost_test_run(regex_regress ${R_SOURCES} 
    DEPENDS boost_regex STATIC)
endif()

boost_test_run(regex_regress_dll ${R_SOURCES} 
  COMPILE_FLAGS "-DBOOST_REGEX_DYN_LINK=1"
  DEPENDS boost_regex 
  EXTRA_OPTIONS SHARED)

boost_test_run(regex_regress_threaded ${R_SOURCES} 
  COMPILE_FLAGS "-DTEST_THREADS -DBOOST_REGEX_DYN_LINK=1"
  DEPENDS boost_regex boost_thread
  EXTRA_OPTIONS SHARED MULTI_THREADED)

regex_test(posix_api_check c_compiler_checks/posix_api_check.c)
boost_test_compile(wide_posix_api_check_c c_compiler_checks/wide_posix_api_check.c)
regex_test(posix_api_check_cpp c_compiler_checks/wide_posix_api_check.cpp)
regex_test(bad_expression_test pathology/bad_expression_test.cpp)
regex_test(recursion_test pathology/recursion_test.cpp)
regex_test(unicode_iterator_test unicode/unicode_iterator_test.cpp)

boost_test_run(static_mutex_test static_mutex/static_mutex_test.cpp
  COMPILE_FLAGS "-DBOOST_REGEX_DYN_LINK=1"
  DEPENDS boost_regex boost_thread
  EXTRA_OPTIONS MULTI_THREADED SHARED)

regex_test(object_cache_test object_cache/object_cache_test.cpp)

if(NOT ICU_FOUND)
  boost_test_run(regex_config_info config_info/regex_config_info.cpp
    DEPENDS boost_regex 
    EXTRA_OPTIONS STATIC)
endif()

boost_test_run(regex_dll_config_info config_info/regex_config_info.cpp
  COMPILE_FLAGS "-DBOOST_REGEX_DYN_LINK=1"
  DEPENDS boost_regex 
  EXTRA_OPTIONS SHARED)

regex_test(test_collate_info collate_info/collate_info.cpp)

boost_test_compile(concept_check concepts/concept_check.cpp)
boost_test_compile(ice_concept_check concepts/icu_concept_check.cpp)

# TODO: Deal with this
  #  [ run
    # sources
#    captures/captures_test.cpp
 #   captures//boost_regex_extra
 #:  # additional args
 #:  # test-files
 #:  # requirements
 #   <threading>multi
 #   <define>BOOST_REGEX_MATCH_EXTRA=1
 #   <define>BOOST_REGEX_NO_LIB=1
# :  # test name
 #   captures_test
# ]
