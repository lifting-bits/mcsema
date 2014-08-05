project( protoc )

include( ../protobuf-common.cmake )

set(SOURCES
  ${PROTOBUF_ROOT}/src/google/protobuf/compiler/main.cc
)

add_definitions(
  -D_CONSOLE
)

add_executable( protoc ${SOURCES} )
target_link_libraries( protoc libprotoc libprotobuf )
if( UNIX )
  target_link_libraries( protoc -lpthread )
endif()
