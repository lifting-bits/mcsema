include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/../PELib ${CMAKE_CURRENT_BINARY_DIR}/../../llvm-3.5/lib/Target/X86
${CMAKE_CURRENT_SOURCE_DIR}/../../llvm-3.5/lib/Target/X86 )

include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR}/../binary_common ${PROTOBUF_INCLUDE_DIR})

add_library(peToCFG peToCFG.cpp inst_decoder_fe.cpp)

add_dependencies(peToCFG LLVMX86CodeGen binary_common)
