#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
cmake_minimum_required(VERSION 2.6)
project(CompileTest)
add_library(compile-test STATIC ${SOURCE})
include_directories(${INCLUDES})
set_source_files_properties(${SOURCE}
  PROPERTIES COMPILE_FLAGS "${COMPILE_FLAGS}")