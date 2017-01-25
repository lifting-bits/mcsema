project(mc-sema)
cmake_minimum_required(VERSION 2.8)

if(WIN32)
SET(CMAKE_EXE_LINKER_FLAGS "/LARGEADDRESSAWARE ${CMAKE_EXE_LINKER_FLAGS}")
endif(WIN32)

add_subdirectory(llvm-3.5)
add_subdirectory(mc-sema)
