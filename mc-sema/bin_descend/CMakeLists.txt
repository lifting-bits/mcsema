include_directories( ${CMAKE_CURRENT_BINARY_DIR}/../../llvm-3.5/lib/Target/X86
  ${CMAKE_CURRENT_SOURCE_DIR}/../../llvm-3.5/lib/Target/X86
  ${CMAKE_CURRENT_SOURCE_DIR}/../peToCFG
  ${CMAKE_CURRENT_SOURCE_DIR}/../cfgToLLVM 
  ${CMAKE_CURRENT_SOURCE_DIR}/../binary_common )


include_directories(${CMAKE_CURRENT_BINARY_DIR} ${PROTOBUF_INCLUDE_DIR} ${PROTO_SRCS} ${PROTO_HDRS})


link_directories(${CMAKE_CURRENT_BINARY_DIR}/../../lib)
add_executable(bin_descend bin_descend.cpp cfg_recover.cpp ExternalFuncMap.cpp) 

target_link_libraries(bin_descend binary_common pe-parser-library cfgToLLVM peToCFG LLVMBitReader LLVMBitWriter
  LLVMMCDisassembler LLVMX86Disassembler LLVMX86AsmParser LLVMX86CodeGen
    LLVMSelectionDAG LLVMAsmPrinter LLVMX86Desc LLVMX86Info
      LLVMX86AsmPrinter LLVMX86Utils ${Boost_LIBRARIES} libprotobuf)

add_dependencies(bin_descend binary_common peToCFG bitreader asmparser bitwriter instrumentation scalaropts ipo LLVMX86CodeGen)

get_target_property(BIN_DESCEND_EXECUTABLE bin_descend LOCATION)
get_filename_component(BIN_DESCEND_PATH ${BIN_DESCEND_EXECUTABLE} PATH)

add_custom_target(
    bin_descend_wrapper ALL
 ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/bin_descend_wrapper.py ${BIN_DESCEND_PATH}/bin_descend_wrapper.py
 SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/bin_descend_wrapper.py
 WORKING_DIRECTORY ${BIN_DESCEND_PATH}
 DEPENDS bin_descend
)

add_custom_target(
    get_cfg_py ALL
 ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/get_cfg.py ${BIN_DESCEND_PATH}/get_cfg.py
 COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/CFG_pb2.py ${BIN_DESCEND_PATH}/CFG_pb2.py
 SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/get_cfg.py ${CMAKE_CURRENT_SOURCE_DIR}/CFG_pb2.py
 WORKING_DIRECTORY ${BIN_DESCEND_PATH}
 DEPENDS bin_descend
)

add_custom_target(
    fake_imports_py ALL
 ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/fake_imports.py ${BIN_DESCEND_PATH}/fake_imports.py
 SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/fake_imports.py
 WORKING_DIRECTORY ${BIN_DESCEND_PATH}
 DEPENDS bin_descend
)

add_custom_target(
    imports_for_dll_py ALL
    ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/imports_for_dll.py ${BIN_DESCEND_PATH}/imports_for_dll.py
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/imports_for_dll.py
    WORKING_DIRECTORY ${BIN_DESCEND_PATH}
    DEPENDS bin_descend
    )
