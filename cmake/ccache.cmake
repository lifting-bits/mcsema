# Copyright (c) 2018-present Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.4)

macro(configureCcache)
  if(NOT "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux" AND
     NOT "${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")

    message(STATUS "ccache: Not supported")

  else()
    find_program(ccache_path ccache)
    if("${ccache_path}" STREQUAL "ccache_path-NOTFOUND")
      message(STATUS "ccache: Not found")
    else()
      set(CMAKE_C_COMPILER_LAUNCHER "${ccache_path}")
      set(CMAKE_CXX_COMPILER_LAUNCHER "${ccache_path}")

      set(ccache_dir "$ENV{CCACHE_DIR}")
      if("${ccache_dir}" STREQUAL "")
        set(ccache_dir "$ENV{HOME}/.ccache")
      endif()

      message(STATUS "ccache: enabled with '${ccache_path}'. The cache folder is located here: '${ccache_dir}'")
    endif()
  endif()
endmacro()
