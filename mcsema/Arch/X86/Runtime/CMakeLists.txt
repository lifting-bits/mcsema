# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

enable_language(ASM)

if (NOT TARGET remill)
    message(FATAL_ERROR "The remill target does not exists!")
endif ()

# Create the Windows runtimes
if(WIN32 AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")

    #TODO(artem): find clang for windows compiler and build
    message(WARNING "Runtime generation is only supported on Windows when building with clang. Runtimes will be unavailable, but mcsema-lift will still work")
    message(WARNING "Did you specify a toolset (for example via -T llvm-vs2013) to cmake?")

elseif(APPLE)
    #TODO(artem): Support runtimes on MacOS
    message(WARNING "Runtime generation is not supported for your operating system. mcsema-lift will still work, but you can't rebuild the generated bitcode to native executables.")
else()    
  # Create the runtimes
  # 32-bit binaries work on both 32 and 64 bit platforms

  if(WIN32)
    add_executable(mcsema-print-runtime-x86
      print_PE_32_windows.cpp)

      target_link_libraries(mcsema-print-runtime-x86 PRIVATE remill) # this is going to import the public include headers of remill
      target_include_directories(mcsema-print-runtime-x86 PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../../../") # todo: HACK! fix this!

    # build a static library from this generated object
    add_library(mcsema_rt32 STATIC mcsema_rt32.obj)
    set_target_properties(mcsema_rt32 PROPERTIES STATIC_LIBRARY_FLAGS "/machine:x86")
    # add_library does not know how to link this thing together from an obj
    # tell cmake its just like C (the same command line will work for the object)
    set_target_properties(
      mcsema_rt32 
      PROPERTIES
      LINKER_LANGUAGE C
      )

    # use a custom step to build asm->obj since cmake wont recognize how to build our asm
    add_custom_command(
      OUTPUT mcsema_rt32.obj
      COMMAND "${CMAKE_C_COMPILER}" -m32 /Fomcsema_rt32.obj /c runtime_32.asm
      DEPENDS runtime_32.asm
      COMMENT "Building Runtime ASM...")
    set_source_files_properties(
      mcsema_rt32.obj
      PROPERTIES
      EXTERNAL_OBJECT True
      GENERATED True)

    add_custom_command(
      OUTPUT runtime_32.asm
      COMMAND mcsema-print-runtime-x86
      DEPENDS mcsema-print-runtime-x86
      COMMENT "Generating 32-bit Windows PE runtime...")
  elseif(UNIX)
    # Linux and friends
    add_compile_options(-Wno-invalid-offsetof)
    
    add_executable(mcsema-print-runtime-x86
      print_ELF_32_linux.cpp)

    target_link_libraries(mcsema-print-runtime-x86 PRIVATE remill) # this is going to import the public include headers of remill
    target_include_directories(mcsema-print-runtime-x86 PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../../../") # todo: HACK! fix this!

    add_library(mcsema_rt32 STATIC runtime_32.S)
    set_target_properties(mcsema_rt32
      PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")

    add_custom_command(
      OUTPUT runtime_32.S
      COMMAND mcsema-print-runtime-x86
      DEPENDS mcsema-print-runtime-x86
      COMMENT "Generating 32-bit Linux ELF runtime...")
  else()
    message(ERROR "Unsupported operating system")
  endif()

  install(
    TARGETS mcsema_rt32
    ARCHIVE DESTINATION lib)
 
  # only do 64-bit binaries on 64-bit platforms
  if( CMAKE_SIZEOF_VOID_P EQUAL 8 )
    if(WIN32)
      add_executable(mcsema-print-runtime-amd64
        print_PE_64_windows.cpp)

        target_link_libraries(mcsema-print-runtime-amd64 PRIVATE remill) # this is going to import the public include headers of remill
        target_include_directories(mcsema-print-runtime-amd64 PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../../../") # todo: HACK! fix this!

      # build a static library from this generated object
      add_library(mcsema_rt64 STATIC mcsema_rt64.obj)
      set_target_properties(mcsema_rt64 PROPERTIES STATIC_LIBRARY_FLAGS "/MACHINE:X64")
      # add_library does not know how to link this thing together from an obj
      # tell cmake its just like C (the same command line will work for the object)
      set_target_properties(
        mcsema_rt64 
        PROPERTIES
        LINKER_LANGUAGE C
        )

      # use a custom step to build asm->obj since cmake wont recognize how to build our asm
      add_custom_command(
        OUTPUT mcsema_rt64.obj
        COMMAND "${CMAKE_C_COMPILER}" -m64 /Fomcsema_rt64.obj /c runtime_64.asm
        DEPENDS runtime_64.asm
        COMMENT "Building Runtime ASM...")
      set_source_files_properties(
        mcsema_rt64.obj
        PROPERTIES
        EXTERNAL_OBJECT True
        GENERATED True)

      add_custom_command(
        OUTPUT runtime_64.asm
        COMMAND mcsema-print-runtime-amd64
        DEPENDS mcsema-print-runtime-amd64
        COMMENT "Generating 64-bit Windows PE runtime...")
    
    elseif(UNIX)
      add_compile_options(-Wno-invalid-offsetof)

      # Linux and friends
      add_executable(mcsema-print-runtime-amd64
        print_ELF_64_linux.cpp)

      target_link_libraries(mcsema-print-runtime-amd64 PRIVATE remill) # this is going to import the public include headers of remill
      target_include_directories(mcsema-print-runtime-amd64 PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../../../") # todo: HACK! fix this!

      add_library(mcsema_rt64 STATIC runtime_64.S)
      set_target_properties(mcsema_rt64
        PROPERTIES COMPILE_FLAGS "-m64" LINK_FLAGS "-m64")

      add_custom_command(
        OUTPUT runtime_64.S
        COMMAND mcsema-print-runtime-amd64
        DEPENDS mcsema-print-runtime-amd64
        COMMENT "Generating 64-bit Linux ELF runtime...")
    else()
      message(ERROR "Unsupported operating system")
    endif()

    install(
      TARGETS mcsema_rt64
      ARCHIVE DESTINATION lib)
  endif()

endif()

