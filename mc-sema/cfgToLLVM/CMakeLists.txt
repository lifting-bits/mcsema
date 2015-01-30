include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../llvm-3.5/lib/Target/X86 ${CMAKE_CURRENT_SOURCE_DIR}/../../llvm-3.5/lib/Target/X86 ${CMAKE_CURRENT_SOURCE_DIR}/../peToCFG)

add_library(cfgToLLVM x86Helpers.cpp x86Instrs.cpp x86Instrs_MOV.cpp
  x86Instrs_SETcc.cpp x86Instrs_Branches.cpp x86Instrs_Stack.cpp
  x86Instrs_String.cpp x86Instrs_INCDECNEG.cpp x86Instrs_Exchanges.cpp
  x86Instrs_ADD.cpp x86Instrs_SUB.cpp x86Instrs_bitops.cpp
  x86Instrs_ShiftRoll.cpp x86Instrs_Misc.cpp x86Instrs_Jcc.cpp
  x86Instrs_CMOV.cpp x86Instrs_MULDIV.cpp x86Instrs_CMPTEST.cpp
  x86Instrs_fpu.cpp x86Instrs_SSE.cpp InstructionDispatch.cpp toLLVM.cpp raiseX86.cpp
  TransExcn.cpp win32cb.cpp JumpTables.cpp postPasses.cpp inlineSpecials.cpp
  win32_Intrinsics.cpp ArchOps.cpp win32ArchOps.cpp linuxArchOps.cpp)

add_dependencies(cfgToLLVM LLVM LLVMX86CodeGen)
