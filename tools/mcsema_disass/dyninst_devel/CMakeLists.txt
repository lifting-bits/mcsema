if (NOT UNIX)
  message (ERROR "The Dyninst frontend currently does not support this OS")
else ()
  add_compile_options(-frtti -std=c++14)
  set (CMAKE_CXX_FLAGS "-std=c++14")
endif ()

find_package(Dyninst REQUIRED)
include_directories(${DYNINST_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../../)

set(MCSEMA_DYNINST_DISASS mcsema-dyninst-devel)

set_source_files_properties(
  ${PROJECT_PROTOBUFSOURCEFILES}
  PROPERTIES GENERATED TRUE
  )

add_executable(${MCSEMA_DYNINST_DISASS}
  main.cpp
  ${PROJECT_PROTOBUFSOURCEFILES}
  CFGWriter.cpp
  ExternalFunctionManager.cpp
  SectionManager.cpp
  MagicSection.cpp
  )

add_dependencies(${MCSEMA_DYNINST_DISASS} generate-protobuf-files)

target_link_libraries(${MCSEMA_DYNINST_DISASS} PRIVATE dyninstAPI symtabAPI parseAPI common instructionAPI protobuf)
target_link_libraries(${MCSEMA_DYNINST_DISASS} PRIVATE ${PROJECT_LIBRARIES})
set_property(TARGET ${MCSEMA_DYNINST_DISASS} APPEND PROPERTY CMAKE_CXX_FLAGS -frtti)
set_target_properties(${MCSEMA_DYNINST_DISASS} PROPERTIES CXX_STANDARD 14 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)

install(
  TARGETS ${MCSEMA_DYNINST_DISASS}
  RUNTIME DESTINATION bin
  )
