
project(mcsema)
cmake_minimum_required(VERSION 2.8)

if(WIN32)
  SET(CMAKE_EXE_LINKER_FLAGS "/LARGEADDRESSAWARE ${CMAKE_EXE_LINKER_FLAGS}")
endif(WIN32)

# Bring in LLVM.
add_subdirectory(${MCSEMA_LLVM_DIR})
set(CMAKE_MODULE_PATH "${MCSEMA_LLVM_DIR}/cmake/modules ${CMAKE_MODULE_PATH}")

find_package(LLVM REQUIRED)
add_definitions(${LLVM_DEFINITIONS})

include_directories(${MCSEMA_DIR})
include_directories(${MCSEMA_DIR}/third_party)
include_directories(${MCSEMA_BUILD_DIR}/include)
include_directories(${MCSEMA_LLVM_DIR}/include)
include_directories(${MCSEMA_LLVM_DIR}/lib/Target/X86/)
include_directories(${MCSEMA_BUILD_DIR}/third_party/llvm/include)
include_directories(${MCSEMA_BUILD_DIR}/third_party/llvm/lib/Target/X86)
include_directories(${MCSEMA_GEN_DIR})

# Make sure we can find the mcsema headers.
include_directories(${MCSEMA_DIR}/mc-sema)
include_directories(${MCSEMA_DIR}/mc-sema/binary_common)
include_directories(${MCSEMA_DIR}/mc-sema/cfgToLLVM)
include_directories(${MCSEMA_DIR}/mc-sema/common)
include_directories(${MCSEMA_DIR}/mc-sema/peToCFG)
include_directories(${MCSEMA_DIR}/mc-sema/cfgToLLVM)

# Make sure we can find libprotobuf
link_directories(${MCSEMA_BUILD_DIR}/lib)

add_compile_options(
  -x c++
  -g3
  -O0
  -std=gnu++11
  -fno-rtti
  -DGOOGLE_PROTOBUF_NO_RTTI)

add_executable(mcsema-lift
  ${MCSEMA_DIR}/mc-sema/Lift.cpp
  ${MCSEMA_DIR}/mc-sema/Arch/Arch.cpp
  ${MCSEMA_DIR}/mc-sema/Arch/X86/Register.cpp
  ${MCSEMA_DIR}/mc-sema/Arch/X86/Dispatch.cpp
  ${MCSEMA_DIR}/mc-sema/BC/Util.cpp
  ${MCSEMA_DIR}/mc-sema/CFG/CFG.cpp
  ${MCSEMA_DIR}/generated/CFG.pb.cc

  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/raiseX86.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Helpers.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86_64Helpers.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/ArchOps.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/JumpTables.cpp

  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/TransExcn.cpp

  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_ADD.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_bitops.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_Branches.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_CMOV.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_CMPTEST.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_Exchanges.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_fpu.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_INCDECNEG.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_Jcc.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_Misc.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_MOV.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_MULDIV.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_SETcc.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_ShiftRoll.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_SSE.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_Stack.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_String.cpp
  ${MCSEMA_DIR}/mc-sema/cfgToLLVM/x86Instrs_SUB.cpp)

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
