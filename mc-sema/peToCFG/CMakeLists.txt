include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/../PELib ${CMAKE_CURRENT_BINARY_DIR}/../../llvm-3.2/lib/Target/X86
${CMAKE_CURRENT_SOURCE_DIR}/../../llvm-3.2/lib/Target/X86 )

PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS CFG.proto)

include_directories(${CMAKE_CURRENT_BINARY_DIR} ${PROTOBUF_INCLUDE_DIR})

add_library(peToCFG ${PROTO_SRCS} ${PROTO_HDRS} peToCFG.cpp inst_decoder_fe.cpp)

add_dependencies(peToCFG LLVM LLVMX86CodeGen)
