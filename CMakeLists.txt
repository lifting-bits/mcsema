# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

project(mcsema)
cmake_minimum_required(VERSION 3.1)

if (NOT MCSEMA_GEN_DIR)
    set(MCSEMA_GEN_DIR "${CMAKE_BINARY_DIR}/mcsema_generated")
endif()

message(STATUS "Generated files will be stored in the following directory: ${MCSEMA_GEN_DIR}")

if(WIN32)
  SET(CMAKE_EXE_LINKER_FLAGS "/LARGEADDRESSAWARE ${CMAKE_EXE_LINKER_FLAGS}")
endif(WIN32)

set(CMAKE_MODULE_PATH "${LLVM_DIR}/cmake/modules ${CMAKE_MODULE_PATH}")

# Configure with the build LLVM
find_package(LLVM 3.8 REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})

set (CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
include (LLVMUtils)
include (GetGitRevisionDescription)

# we need C++11
if(NOT WIN32)
  # WIN32 defaults to CXX11 by default, and setting it explicitly here
  # confuses clang-cl, which will bail out with "unknown flag -std=g++11"
  set(CMAKE_CXX_STANDARD 11)
endif()

# Get protobufs.
if(WIN32)
  # Change the slashes to Unix style or risk the wrath of invalid escape
  # sequences!
  string(REGEX REPLACE "\\\\" "/" CMAKE_SOURCE_DIR ${CMAKE_SOURCE_DIR})

  set(PROTOBUF_ROOT "${CMAKE_SOURCE_DIR}/third_party/protobuf")
  set(Protobuf_LIBRARIES "${PROTOBUF_ROOT}/build/libprotobuf/Release")
  set(Protobuf_INCLUDE_DIR "${PROTOBUF_ROOT}/src")
  
  include_directories(${Protobuf_INCLUDE_DIR})
  link_directories(${Protobuf_LIBRARIES})
elseif(APPLE)
  set(PROTOBUF_ROOT "${CMAKE_SOURCE_DIR}/third_party/protobuf")
  set(Protobuf_LIBRARIES "${PROTOBUF_ROOT}/build/lib")
  set(Protobuf_INCLUDE_DIR "${PROTOBUF_ROOT}/src")
  
  include_directories(${Protobuf_INCLUDE_DIR})
  link_directories(${Protobuf_LIBRARIES})
endif(WIN32)
find_package(Protobuf REQUIRED)

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/third_party)
include_directories(${MCSEMA_LLVM_DIR})
include_directories(${MCSEMA_LLVM_DIR}/include)
include_directories(${MCSEMA_LLVM_DIR}/lib/Target/X86/)
include_directories(${MCSEMA_BUILD_DIR}/include)
include_directories(${MCSEMA_BUILD_DIR}/llvm/include)
include_directories(${MCSEMA_BUILD_DIR}/llvm/lib/Target/X86)
include_directories(${MCSEMA_GEN_DIR})

# Make sure we can find the mcsema headers.
include_directories(${CMAKE_SOURCE_DIR}/mcsema)
include_directories(${CMAKE_SOURCE_DIR}/mcsema/binary_common)
include_directories(${CMAKE_SOURCE_DIR}/mcsema/cfgToLLVM)
include_directories(${CMAKE_SOURCE_DIR}/mcsema/common)
include_directories(${CMAKE_SOURCE_DIR}/mcsema/peToCFG)
include_directories(${CMAKE_SOURCE_DIR}/mcsema/cfgToLLVM)

if(WIN32)
  add_compile_options(
    /nologo
    /DGOOGLE_PROTOBUF_NO_RTTI
    /W3
    /wd4141 # Suppress ''modifier' : used more than once' (because of __forceinline combined with inline)
    /wd4146 # Suppress 'unary minus operator applied to unsigned type, result still unsigned'
    /wd4180 # Suppress 'qualifier applied to function type has no meaning; ignored'
    /wd4244 # Suppress ''argument' : conversion from 'type1' to 'type2', possible loss of data'
    /wd4258 # Suppress ''var' : definition from the for loop is ignored; the definition from the enclosing scope is used'
    /wd4267 # Suppress ''var' : conversion from 'size_t' to 'type', possible loss of data'
    /wd4291 # Suppress ''declaration' : no matching operator delete found; memory will not be freed if initialization throws an exception'
    /wd4345 # Suppress 'behavior change: an object of POD type constructed with an initializer of the form () will be default-initialized'
    /wd4351 # Suppress 'new behavior: elements of array 'array' will be default initialized'
    /wd4355 # Suppress ''this' : used in base member initializer list'
    /wd4456 # Suppress 'declaration of 'var' hides local variable'
    /wd4457 # Suppress 'declaration of 'var' hides function parameter'
    /wd4458 # Suppress 'declaration of 'var' hides class member'
    /wd4459 # Suppress 'declaration of 'var' hides global declaration'
    /wd4503 # Suppress ''identifier' : decorated name length exceeded, name was truncated'
    /wd4624 # Suppress ''derived class' : destructor could not be generated because a base class destructor is inaccessible'
    /wd4722 # Suppress 'function' : destructor never returns, potential memory leak
    /wd4800 # Suppress ''type' : forcing value to bool 'true' or 'false' (performance warning)'
    /wd4100 # Suppress 'unreferenced formal parameter'
    /wd4127 # Suppress 'conditional expression is constant'
    /wd4512 # Suppress 'assignment operator could not be generated'
    /wd4505 # Suppress 'unreferenced local function has been removed'
    /wd4610 # Suppress '<class> can never be instantiated'
    /wd4510 # Suppress 'default constructor could not be generated'
    /wd4702 # Suppress 'unreachable code'
    /wd4245 # Suppress 'signed/unsigned mismatch'
    /wd4706 # Suppress 'assignment within conditional expression'
    /wd4310 # Suppress 'cast truncates constant value'
    /wd4701 # Suppress 'potentially uninitialized local variable'
    /wd4703 # Suppress 'potentially uninitialized local pointer variable'
    /wd4389 # Suppress 'signed/unsigned mismatch'
    /wd4611 # Suppress 'interaction between '_setjmp' and C++ object destruction is non-portable'
    /wd4805 # Suppress 'unsafe mix of type <type> and type <type> in operation'
    /wd4204 # Suppress 'nonstandard extension used : non-constant aggregate initializer'
    /wd4577 # Suppress 'noexcept used with no exception handling mode specified; termination on exception is not guaranteed'
    /wd4091 # Suppress 'typedef: ignored on left of '' when no variable is declared'
        # C4592 is disabled because of false positives in Visual Studio 2015
        # Update 1. Re-evaluate the usefulness of this diagnostic with Update 2.
    /wd4592 # Suppress ''var': symbol will be dynamically initialized (implementation limitation)

	# Ideally, we'd like this warning to be enabled, but MSVC 2013 doesn't
	# support the 'aligned' attribute in the way that clang sources requires (for
	# any code that uses the LLVM_ALIGNAS macro), so this is must be disabled to
	# avoid unwanted alignment warnings.
	# When we switch to requiring a version of MSVC that supports the 'alignas'
	# specifier (MSVC 2015?) this warning can be re-enabled.
    /wd4324 # Suppress 'structure was padded due to __declspec(align())'
    /D_CRT_SECURE_NO_DEPRECATE
    /D_CRT_SECURE_NO_WARNINGS
    /D_CRT_NONSTDC_NO_DEPRECATE
    /D_CRT_NONSTDC_NO_WARNINGS
    /D_SCL_SECURE_NO_DEPRECATE
    /D_SCL_SECURE_NO_WARNINGS
    )
else()
  add_compile_options(
    -g3
    -O0)

  if(NOT LLVM_ENABLE_RTTI)
    add_compile_options(
      -fno-rtti
      -DGOOGLE_PROTOBUF_NO_RTTI)
  endif()
endif(WIN32)

# configure a header file to pass some of the CMake settings
# to the source code

git_describe(MCSEMA_VERSION_STRING)
git_get_branch(MCSEMA_BRANCH_NAME)

if(NOT MCSEMA_VERSION_STRING)
  set(MCSEMA_VERSION_STRING "unknown")
endif()

if(NOT MCSEMA_BRANCH_NAME)
  set(MCSEMA_BRANCH_NAME "unknown")
endif()

configure_file (
  "mcsema/Version.h.in" #input is based on CMAKE_SOURCE_DIR
  "${MCSEMA_GEN_DIR}/Version.h" #output is based on CMAKE_BINARY_DIR
)

# Make sure we find Version.h
include_directories("${CMAKE_BINARY_DIR}")

#
# protobuf file generation
# this will make sure that the protobuf files are generated each time
# the CFG.h header file is modified
#
# todo: use find protobuf CMake module to generate the files; this is
# not easy on windows right now, since protoc is built on the fly.
#

set(PROTOBUF_CONFIGURATION "${CMAKE_SOURCE_DIR}/mcsema/CFG/CFG.proto")

set(PROTOBUF_OUTPUT_FILE_LIST
    "${MCSEMA_GEN_DIR}/CFG.pb.cc"
    "${MCSEMA_GEN_DIR}/CFG.pb.h"
    "${MCSEMA_GEN_DIR}/CFG_pb2.py"
)

if (WIN32)
    set(PROTOC_EXECUTABLE_PATH "${CMAKE_SOURCE_DIR}/third_party/protobuf/build/protoc/Release/protoc.exe")
else ()
    set(PROTOC_EXECUTABLE_PATH "protoc")
endif()

add_custom_command(
    OUTPUT ${PROTOBUF_OUTPUT_FILE_LIST}

    COMMAND "${PROTOC_EXECUTABLE_PATH}" --cpp_out "${MCSEMA_GEN_DIR}" --python_out "${MCSEMA_GEN_DIR}" --proto_path "${CMAKE_SOURCE_DIR}/mcsema/CFG" "${PROTOBUF_CONFIGURATION}"

    DEPENDS "${CMAKE_SOURCE_DIR}/mcsema/CFG/CFG.h"
    MAIN_DEPENDENCY "${PROTOBUF_CONFIGURATION}"

    COMMENT "Generating protobuf files..."
    VERBATIM
)

# mcsema source files
add_executable(mcsema-lift
  ${CMAKE_SOURCE_DIR}/mcsema/Lift.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/Arch.cpp
  
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Dispatch.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Lift.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Register.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Util.cpp

  ${CMAKE_SOURCE_DIR}/mcsema/BC/Lift.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/BC/Util.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/CFG/CFG.cpp
  ${CMAKE_BINARY_DIR}/mcsema_generated/CFG.pb.cc

  ${CMAKE_SOURCE_DIR}/mcsema/cfgToLLVM/JumpTables.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/cfgToLLVM/TransExcn.cpp

  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/ADD.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/bitops.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/Branches.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/CMOV.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/CMPTEST.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/Exchanges.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/fpu.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/INCDECNEG.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/Jcc.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/Misc.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/MOV.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/MULDIV.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/SETcc.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/ShiftRoll.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/SSE.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/Stack.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/String.cpp
  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/SUB.cpp)

target_link_libraries(mcsema-lift
  protobuf
  LLVMBitReader
  LLVMBitWriter
  LLVMMCDisassembler
  LLVMX86Disassembler
  LLVMX86AsmParser
  LLVMX86CodeGen
  LLVMSelectionDAG
  LLVMAsmPrinter
  LLVMX86Desc
  LLVMX86Info
  LLVMX86AsmPrinter
  LLVMX86Utils
  LLVMipo
  LLVMTransformUtils
  LLVMScalarOpts
  LLVMInstrumentation
  LLVMObjCARCOpts)

#TODO(artem):  Make this ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86 and have a 
# CMakeLists.txt there add any relevant subdirs
add_subdirectory(${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/Bitcode)
add_subdirectory(${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Runtime)

install(
  TARGETS mcsema-lift 
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib)

install(FILES "${MCSEMA_GEN_DIR}/CFG_pb2.py" DESTINATION "${CMAKE_SOURCE_DIR}/tools/mcsema_disass/ida")
