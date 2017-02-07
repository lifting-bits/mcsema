cmake_minimum_required(VERSION 2.8)

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules"
)

add_definitions(-D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS)
#include_directories(${LLVM_DIR}/include)

add_subdirectory(${LLVM_DIR})


# add_subdirectory(cfgToLLVM)
# add_subdirectory(peToCFG)
# add_subdirectory(bitcode_from_cfg)
# add_subdirectory(binary_common)
# add_subdirectory(bin_descend)
# add_subdirectory(runtime)
