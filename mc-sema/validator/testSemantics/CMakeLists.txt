find_package(Nasm REQUIRED)
include_directories(${LLVM_MAIN_SRC_DIR}/utils/unittest/googletest/include 
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../peToCFG 
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../cfgToLLVM 
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../../llvm-3.2/utils/unittest/googletest/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../../llvm-3.2/lib/Target/X86
                    ${CMAKE_CURRENT_BINARY_DIR}/../../../llvm-3.2/lib/Target/X86)

SET_SOURCE_FILES_PROPERTIES( "${CMAKE_CURRENT_SOURCE_DIR}/testSemantics.auto.cpp" 
	PROPERTIES
	GENERATED true
	)

add_custom_target(testSemantics.auto.cpp ALL
	COMMAND ${PYTHON_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/../testgen.py" -tstmpl "${CMAKE_CURRENT_SOURCE_DIR}/testSemantics.template" -tsout "${CMAKE_CURRENT_SOURCE_DIR}/testSemantics.auto.cpp" -testfiles "${CMAKE_CURRENT_SOURCE_DIR}/../tests" -nasm "${NASM_EXECUTABLE}"
	COMMENT Generating semantics tests
)
add_executable(testSemantics "${CMAKE_CURRENT_SOURCE_DIR}/testSemantics.auto.cpp" )
add_dependencies(testSemantics testSemantics.auto.cpp )

link_directories(${CMAKE_CURRENT_BINARY_DIR}/../../../lib)

target_link_libraries(testSemantics peToCFG cfgToLLVM 
  LLVMInterpreter LLVMipo LLVMInstrumentation
  LLVMX86CodeGen LLVMJIT LLVMBitReader LLVMBitWriter LLVMMCDisassembler gtest
  gtest_main LLVMX86Disassembler LLVMX86AsmParser LLVMX86CodeGen
    LLVMSelectionDAG LLVMAsmPrinter LLVMX86Desc LLVMX86Info
      LLVMX86AsmPrinter LLVMX86Utils ${Boost_LIBRARIES} libprotobuf)

IF(UNIX)
    find_library(DL_LIB dl)
    target_link_libraries(testSemantics ${DL_LIB})
endif(UNIX)

add_dependencies(testSemantics peToCFG bitreader asmparser bitwriter instrumentation scalaropts ipo pin_validator)

IF(APPLE)
    SET_TARGET_PROPERTIES(testSemantics PROPERTIES LINK_FLAGS "-pagezero_size 1000")
endif(APPLE)
