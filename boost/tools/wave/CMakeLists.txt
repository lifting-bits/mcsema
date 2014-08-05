#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
# DPG: tools need modular dependencies just like libraries have
# them. For now, we just include the appropriate directories.

boost_tool_project(Wave
  DESCRIPTION "Boost wave, the C preprocessor")

boost_add_executable(wave 

  cpp.cpp 

  DEPENDS boost_wave boost_program_options boost_filesystem boost_serialization

  MULTI_THREADED
  SHARED
  RELEASE
  )
