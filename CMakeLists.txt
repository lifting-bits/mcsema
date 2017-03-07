# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

project(mcsema)
cmake_minimum_required(VERSION 2.8)

if(WIN32)
  SET(CMAKE_EXE_LINKER_FLAGS "/LARGEADDRESSAWARE ${CMAKE_EXE_LINKER_FLAGS}")
endif(WIN32)

set(CMAKE_MODULE_PATH "${LLVM_DIR}/cmake/modules ${CMAKE_MODULE_PATH}")

# Configure with the build LLVM
find_package(LLVM 3.8 REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})

# Get protobufs.
if(WIN32)
  # Change the slashes to Unix style or risk the wrath of invalid escape
  # sequences!
  string(REGEX REPLACE "\\\\" "/" MCSEMA_DIR ${MCSEMA_DIR})

  set(PROTOBUF_ROOT "${MCSEMA_DIR}/third_party/protobuf")
  set(Protobuf_LIBRARIES "${PROTOBUF_ROOT}/build/libprotobuf/Release")
  set(Protobuf_INCLUDE_DIR "${PROTOBUF_ROOT}/src")
  
  include_directories(${Protobuf_INCLUDE_DIR})
  link_directories(${Protobuf_LIBRARIES})
endif(WIN32)
find_package(Protobuf REQUIRED)

include_directories(${MCSEMA_DIR})
include_directories(${MCSEMA_DIR}/third_party)
include_directories(${MCSEMA_LLVM_DIR})
include_directories(${MCSEMA_LLVM_DIR}/include)
include_directories(${MCSEMA_LLVM_DIR}/lib/Target/X86/)
include_directories(${MCSEMA_BUILD_DIR}/include)
include_directories(${MCSEMA_BUILD_DIR}/llvm/include)
include_directories(${MCSEMA_BUILD_DIR}/llvm/lib/Target/X86)
include_directories(${MCSEMA_GEN_DIR})

# Make sure we can find the mcsema headers.
include_directories(${MCSEMA_DIR}/mcsema)
include_directories(${MCSEMA_DIR}/mcsema/binary_common)
include_directories(${MCSEMA_DIR}/mcsema/cfgToLLVM)
include_directories(${MCSEMA_DIR}/mcsema/common)
include_directories(${MCSEMA_DIR}/mcsema/peToCFG)
include_directories(${MCSEMA_DIR}/mcsema/cfgToLLVM)

if(WIN32)
  add_compile_options(
    /nologo
    /DGOOGLE_PROTOBUF_NO_RTTI
    /W3)
else()
  add_compile_options(
    -x c++
    -g3
    -O0
    -std=gnu++11
    -fno-rtti
    -DGOOGLE_PROTOBUF_NO_RTTI)
endif(WIN32)

add_executable(mcsema-lift
  ${MCSEMA_DIR}/mcsema/Lift.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Arch.cpp
  
  ${MCSEMA_DIR}/mcsema/Arch/X86/Dispatch.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Lift.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Register.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Util.cpp

  ${MCSEMA_DIR}/mcsema/BC/Lift.cpp
  ${MCSEMA_DIR}/mcsema/BC/Util.cpp
  ${MCSEMA_DIR}/mcsema/CFG/CFG.cpp
  ${MCSEMA_DIR}/generated/CFG.pb.cc

  ${MCSEMA_DIR}/mcsema/cfgToLLVM/JumpTables.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/TransExcn.cpp

  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/ADD.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/bitops.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/Branches.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/CMOV.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/CMPTEST.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/Exchanges.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/fpu.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/INCDECNEG.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/Jcc.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/Misc.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/MOV.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/MULDIV.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/SETcc.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/ShiftRoll.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/SSE.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/Stack.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/String.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/SUB.cpp)

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

install(
  TARGETS mcsema-lift
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib)
