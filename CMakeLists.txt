# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

project(mcsema)
cmake_minimum_required(VERSION 2.8)

set(MCSEMA_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(MCSEMA_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(MCSEMA_LLVM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/llvm)
set(MCSEMA_LLVM_BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build/llvm)
set(MCSEMA_GEN_DIR ${CMAKE_CURRENT_SOURCE_DIR}/generated)

if(WIN32)
  SET(CMAKE_EXE_LINKER_FLAGS "/LARGEADDRESSAWARE ${CMAKE_EXE_LINKER_FLAGS}")
endif(WIN32)

set(CMAKE_MODULE_PATH "${LLVM_DIR}/cmake/modules;${CMAKE_MODULE_PATH}")

# Configure with the build LLVM
find_package(LLVM 3.8 REQUIRED CONFIG HINTS ${MCSEMA_LLVM_BUILD_DIR}/share/llvm/cmake)
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
include_directories(${MCSEMA_LLVM_DIR}/lib/Target/X86)
include_directories(${MCSEMA_LLVM_DIR}/lib/Target/Mips)
include_directories(${MCSEMA_BUILD_DIR}/include)
include_directories(${MCSEMA_LLVM_BUILD_DIR}/include)
include_directories(${MCSEMA_LLVM_BUILD_DIR}/lib/Target/X86)
include_directories(${MCSEMA_LLVM_BUILD_DIR}/lib/Target/Mips)
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
    -g3
    -O0
    -std=gnu++11)
    #-fno-rtti
    #-DGOOGLE_PROTOBUF_NO_RTTI)
endif(WIN32)

add_executable(mcsema-lift
  ${MCSEMA_DIR}/mcsema/Lift.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Arch.cpp
  
  ${MCSEMA_DIR}/mcsema/Arch/X86/Dispatch.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Lift.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Register.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Util.cpp

  ${MCSEMA_DIR}/mcsema/Arch/Mips/Register.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Dispatch.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Lift.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/ADDiu.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/ADDu.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/B.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/Bcc.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/JAL.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/JR.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/LUi.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/LW.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/OR.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/SB.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/SW.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/JALR.cpp

  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/ADD.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/ADDi.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/AND.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/ANDi.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/XOR.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/NOR.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/MFLO.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/SUB.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/SUBu.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/SLT.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/SLTu.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/SLTiu.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/SLTi.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/SLL.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/SRL.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/ORi.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/DIV.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/J.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/LHu.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/MFC0.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/SH.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/MULT.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/SRA.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Mips/Semantics/LBu.cpp

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
  LLVMMipsDisassembler
  LLVMX86AsmParser
  LLVMMipsAsmParser
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

#target_compile_options(mcsema-lift PUBLIC
#        -fno-rtti
#        -DGOOGLE_PROTOBUF_NO_RTTI)

install(
  TARGETS mcsema-lift
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib)


add_subdirectory(python)
