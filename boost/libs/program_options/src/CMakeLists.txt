#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_add_library(program_options
  cmdline.cpp config_file.cpp options_description.cpp parsers.cpp 
  split.cpp variables_map.cpp value_semantic.cpp positional_options.cpp 
  utf8_codecvt_facet.cpp convert.cpp winmain.cpp
  SHARED_COMPILE_FLAGS "-DBOOST_PROGRAM_OPTIONS_DYN_LINK=1")
