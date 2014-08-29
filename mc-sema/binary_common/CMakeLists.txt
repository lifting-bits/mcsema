include_directories( ${CMAKE_CURRENT_BINARY_DIR}/../../llvm-3.2/lib/Target/X86
${CMAKE_CURRENT_SOURCE_DIR}/../../llvm-3.2/lib/Target/X86 )

add_subdirectory(pe-parse)

include_directories(${CMAKE_CURRENT_BINARY_DIR} ${PROTOBUF_INCLUDE_DIR})

add_library(binary_common ${PROTO_SRCS} ${PROTO_HDRS} bincomm.cpp ELFTarget.cpp PETarget.cpp)
