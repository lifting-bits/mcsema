include_directories(
  ${CMAKE_CURRENT_BINARY_DIR}/../../llvm-3.5/lib/Target/X86 ${CMAKE_CURRENT_SOURCE_DIR}/../../llvm-3.5/lib/Target/X86
  ${CMAKE_CURRENT_SOURCE_DIR}/../peToCFG
  ${CMAKE_CURRENT_SOURCE_DIR}/../cfgToLLVM )

link_directories(
  ${CMAKE_CURRENT_BINARY_DIR}/../../llvm-3.5/lib)

link_directories(
  ${CMAKE_CURRENT_BINARY_DIR}/../../lib)

add_executable(cfg_to_bc
  cfg_to_bc.cpp) 

target_link_libraries(cfg_to_bc
  cfgToLLVM
  peToCFG
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
  LLVMObjCARCOpts
  ${Boost_LIBRARIES}
  libprotobuf)

add_dependencies(cfg_to_bc
  peToCFG)
