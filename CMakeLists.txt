# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

project(mcsema)

include_directories(${PROJECT_SOURCE_DIR})

add_executable(mcsema-lift
  EXCLUDE_FROM_ALL
  generated/CFG.pb.cc
  mcsema/Arch/Arch.cpp
  mcsema/CFG/CFG.cpp
  mcsema/BC/Instruction.cpp
  mcsema/BC/Lift.cpp
  mcsema/BC/Optimize.cpp
  mcsema/BC/Util.cpp
  mcsema/Lift.cpp
)

add_dependencies(mcsema-lift
  semantics
)

target_link_libraries(mcsema-lift
  remill
)

#include_directories(${CMAKE_SOURCE_DIR}/third_party)
#include_directories(${MCSEMA_LLVM_DIR})
#include_directories(${MCSEMA_LLVM_DIR}/include)
#include_directories(${MCSEMA_LLVM_DIR}/lib/Target/X86/)
#include_directories(${MCSEMA_BUILD_DIR}/include)
#include_directories(${MCSEMA_BUILD_DIR}/llvm/include)
#include_directories(${MCSEMA_BUILD_DIR}/llvm/lib/Target/X86)
#include_directories(${MCSEMA_GEN_DIR})
#
## Make sure we can find the mcsema headers.
#include_directories(${CMAKE_SOURCE_DIR}/mcsema)
#include_directories(${CMAKE_SOURCE_DIR}/mcsema/binary_common)
#include_directories(${CMAKE_SOURCE_DIR}/mcsema/cfgToLLVM)
#include_directories(${CMAKE_SOURCE_DIR}/mcsema/common)
#include_directories(${CMAKE_SOURCE_DIR}/mcsema/peToCFG)
#include_directories(${CMAKE_SOURCE_DIR}/mcsema/cfgToLLVM)


#add_executable(mcsema-lift
#  ${CMAKE_SOURCE_DIR}/mcsema/Lift.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/Arch.cpp
#  
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Dispatch.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Lift.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Register.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Util.cpp
#
#  ${CMAKE_SOURCE_DIR}/mcsema/BC/Lift.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/BC/Util.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/CFG/CFG.cpp
#  ${CMAKE_SOURCE_DIR}/generated/CFG.pb.cc
#
#  ${CMAKE_SOURCE_DIR}/mcsema/cfgToLLVM/JumpTables.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/cfgToLLVM/TransExcn.cpp
#
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/ADD.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/bitops.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/Branches.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/CMOV.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/CMPTEST.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/Exchanges.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/fpu.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/INCDECNEG.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/Jcc.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/Misc.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/MOV.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/MULDIV.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/SETcc.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/ShiftRoll.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/SSE.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/Stack.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/String.cpp
#  ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/SUB.cpp)
#
#target_link_libraries(mcsema-lift
#  protobuf
#  LLVMBitReader
#  LLVMBitWriter
#  LLVMMCDisassembler
#  LLVMX86Disassembler
#  LLVMX86AsmParser
#  LLVMX86CodeGen
#  LLVMSelectionDAG
#  LLVMAsmPrinter
#  LLVMX86Desc
#  LLVMX86Info
#  LLVMX86AsmPrinter
#  LLVMX86Utils
#  LLVMipo
#  LLVMTransformUtils
#  LLVMScalarOpts
#  LLVMInstrumentation
#  LLVMObjCARCOpts)
#
##TODO(artem):  Make this ${CMAKE_SOURCE_DIR}/mcsema/Arch/X86 and have a 
## CMakeLists.txt there add any relevant subdirs
#add_subdirectory(${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Semantics/Bitcode)
#add_subdirectory(${CMAKE_SOURCE_DIR}/mcsema/Arch/X86/Runtime)
#
#install(
#  TARGETS mcsema-lift 
#  RUNTIME DESTINATION bin
#  LIBRARY DESTINATION lib)
