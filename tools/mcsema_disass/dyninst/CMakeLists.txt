if (NOT UNIX)
  message (ERROR "The Dyninst frontend currently does not support this OS")
else ()
  add_compile_options(-frtti -std=c++1z)
  set (CMAKE_CXX_FLAGS "-std=c++1z")
endif ()

find_package(Dyninst REQUIRED)
include_directories(${DYNINST_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../../)

set_source_files_properties(
  ${PROJECT_PROTOBUFSOURCEFILES}
  PROPERTIES GENERATED TRUE
  )

add_executable(mcsema-dyninst-disass
  main.cpp
  ArgParser.cpp
  ${PROJECT_PROTOBUFSOURCEFILES}
  CFGWriter.cpp
  ExternalFunc.cpp
  ExternalFunctionManager.cpp
  SectionManager.cpp
  )

add_dependencies(mcsema-dyninst-disass generate-protobuf-files)

target_link_libraries(mcsema-dyninst-disass dyninstAPI symtabAPI parseAPI common instructionAPI protobuf)
set_property(TARGET mcsema-dyninst-disass APPEND PROPERTY CMAKE_CXX_FLAGS -frtti)
set_target_properties(mcsema-dyninst-disass PROPERTIES CXX_STANDARD 14 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)

install(
  TARGETS mcsema-dyninst-disass
  RUNTIME DESTINATION bin
  )
