#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_add_library(wave 

  instantiate_cpp_exprgrammar.cpp
  instantiate_cpp_grammar.cpp
  instantiate_cpp_literalgrs.cpp
  instantiate_defined_grammar.cpp
  instantiate_predef_macros.cpp
  instantiate_re2c_lexer.cpp
  instantiate_re2c_lexer_str.cpp
  token_ids.cpp
  wave_config_constant.cpp
  cpplexer/re2clex/aq.cpp
  cpplexer/re2clex/cpp_re.cpp

  DEPENDS boost_filesystem boost_thread boost_date_time
  SHARED_COMPILE_FLAGS "-DBOOST_ALL_DYN_LINK=1"
  NO_SINGLE_THREADED
  )
