#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
#----------------------------------------------------------------------------
# This file was automatically generated from the original CMakeLists.txt file
# Add a variable to hold the headers for the library
set (lib_headers
    spirit.hpp
    spirit
)

# Add a library target to the build system
boost_library_project(
  spirit
  #  SRCDIRS 
  TESTDIRS  test
  EXAMPLEDIRS
    example/qi/calc6
    example/qi/calc7
    example/qi
    example/qi/mini_c
    example/lex/static_lexer
    example/lex
    example/karma
    example/support
    # example/scheme/test/qi
    example/scheme/test/utree
    example/scheme/test/scheme
    example/scheme/example/sexpr
    # example/scheme/example/generate_qiexpr
    example/scheme/example/scheme
    # example/scheme/example/parse_qiexpr
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "LL parser framework represents parsers directly as EBNF grammars in inlined C++."
  MODULARIZED
  AUTHORS  "Joel de Guzman <joel -at- boost-consulting.com>"
           "Hartmut Kaiser <hartmut.kaiser -at- gmail.com>"
           "Dan Nuffer"
  #  MAINTAINERS 
)


