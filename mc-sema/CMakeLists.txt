cmake_minimum_required(VERSION 2.8)

option(MCSEMA_ENABLE_PIN_VALIDATOR ON)

set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules"
)

set(PROTOBUF_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/protobuf-2.5.0)
if( WIN32 OR CYGWIN)
  # MinGW warns if -fvisibility-inlines-hidden is used.
else()
  include(CheckCXXCompilerFlag)
  check_cxx_compiler_flag("-fvisibility-inlines-hidden" SUPPORTS_FVISIBILITY_INLINES_HIDDEN_FLAG)
  if( SUPPORTS_FVISIBILITY_INLINES_HIDDEN_FLAG )
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility-inlines-hidden")
  endif()

  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()
add_subdirectory(protobuf-cmake)

function(PROTOBUF_GENERATE_CPP SRCS HDRS)
  if(NOT ARGN)
    message(SEND_ERROR "Error: PROTOBUF_GENERATE_CPP() called without any proto files")
    return()
  endif()

  if(PROTOBUF_GENERATE_CPP_APPEND_PATH)
    # Create an include path for each file specified
    foreach(FIL ${ARGN})
      get_filename_component(ABS_FIL ${FIL} ABSOLUTE)
      get_filename_component(ABS_PATH ${ABS_FIL} PATH)
      list(FIND _protobuf_include_path ${ABS_PATH} _contains_already)
      if(${_contains_already} EQUAL -1)
          list(APPEND _protobuf_include_path -I ${ABS_PATH})
      endif()
    endforeach()
  else()
    set(_protobuf_include_path -I ${CMAKE_CURRENT_SOURCE_DIR})
  endif()

  if(DEFINED PROTOBUF_IMPORT_DIRS)
    foreach(DIR ${PROTOBUF_IMPORT_DIRS})
      get_filename_component(ABS_PATH ${DIR} ABSOLUTE)
      list(FIND _protobuf_include_path ${ABS_PATH} _contains_already)
      if(${_contains_already} EQUAL -1)
          list(APPEND _protobuf_include_path -I ${ABS_PATH})
      endif()
    endforeach()
  endif()

  set(${SRCS})
  set(${HDRS})
  foreach(FIL ${ARGN})
    get_filename_component(ABS_FIL ${FIL} ABSOLUTE)
    get_filename_component(FIL_WE ${FIL} NAME_WE)

    list(APPEND ${SRCS} "${CMAKE_CURRENT_BINARY_DIR}/${FIL_WE}.pb.cc")
    list(APPEND ${HDRS} "${CMAKE_CURRENT_BINARY_DIR}/${FIL_WE}.pb.h")

    add_custom_command(
      OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${FIL_WE}.pb.cc"
             "${CMAKE_CURRENT_BINARY_DIR}/${FIL_WE}.pb.h"
      COMMAND  protoc
      ARGS --cpp_out  ${CMAKE_CURRENT_BINARY_DIR} ${_protobuf_include_path} ${ABS_FIL}
      DEPENDS ${ABS_FIL}
      COMMENT "Running C++ protocol buffer compiler on ${FIL}"
      VERBATIM )
  endforeach()

  set_source_files_properties(${${SRCS}} ${${HDRS}} PROPERTIES GENERATED TRUE)
  set(${SRCS} ${${SRCS}} PARENT_SCOPE)
  set(${HDRS} ${${HDRS}} PARENT_SCOPE)
endfunction()

#variable for debug or not 
find_package(Threads REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/common)
set(PROTOBUF_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/protobuf-2.5.0/src)

set(TARGET "X86_64")
if("${TARGET}" STREQUAL "X86_64")
  add_definitions(-DTARGET_IA64)
endif()

add_definitions(-D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../llvm-3.5/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../llvm-3.5/include)

add_subdirectory(cfgToLLVM)
add_subdirectory(peToCFG)
add_subdirectory(bitcode_from_cfg)
add_subdirectory(binary_common)
add_subdirectory(bin_descend)
add_subdirectory(runtime)

if(MCSEMA_ENABLE_PIN_VALIDATOR)
	find_package(Pin)
	if(NOT PIN_FOUND AND NOT WIN32)
	
		if(UNIX)
			set(PIN_DOWNLOAD_URL https://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-67254-gcc.4.4.7-linux.tar.gz)
			set(PIN_DOWNLOAD_HASH 792eaaa199e9deba84cde79858e93ffc)
		endif(UNIX)
	
		if(APPLE)
			set(PIN_DOWNLOAD_URL https://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-67254-clang.5.1-mac.tar.gz)
			set(PIN_DOWNLOAD_HASH 0f93c64484d039ceca828cd2909d321b)
		endif(APPLE)
	
		ExternalProject_add(Pin
			URL ${PIN_DOWNLOAD_URL}
			URL_MD5 ${PIN_DOWNLOAD_HASH}
			CONFIGURE_COMMAND ""
			BUILD_COMMAND ""
			SOURCE_DIR pin
			INSTALL_COMMAND ""
		)
	
		set(PIN_PATH ${CMAKE_CURRENT_BINARY_DIR}/pin)
		set(PIN_EXECUTABLE ${CMAKE_CURRENT_BINARY_DIR}/pin/pin)
	
		add_subdirectory(validator)
	endif(NOT PIN_FOUND AND NOT WIN32)
	
	if(WIN32 AND PIN_FOUND)
		add_subdirectory(validator)
	endif(WIN32 AND PIN_FOUND)
endif(MCSEMA_ENABLE_PIN_VALIDATOR)
