# Copyright (c) 2020 Trail of Bits, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

enable_language(ASM)

if (NOT TARGET remill)
  message(FATAL_ERROR "The remill target does not exists!")
endif ()

if(DEFINED WIN32)
  set(install_folder "${CMAKE_INSTALL_PREFIX}/mcsema")
else()
  set(install_folder "${CMAKE_INSTALL_PREFIX}")
endif()

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

  set(MCSMEMA_RT32 mcsema_rt32-${LLVM_MAJOR_VERSION}.${LLVM_MINOR_VERSION})
  set(MCSMEMA_RT64 mcsema_rt64-${LLVM_MAJOR_VERSION}.${LLVM_MINOR_VERSION})

  if(WIN32)
    add_executable(mcsema-print-runtime-x86
      print_PE_32_windows.cpp
    )

    # this is going to import the public include headers of remill
    target_link_libraries(mcsema-print-runtime-x86 PRIVATE remill)
    target_include_directories(mcsema-print-runtime-x86 PRIVATE
      "${REMILL_INCLUDE_LOCATION}" "${MCSEMA_SOURCE_DIR}"
    )

    # build a static library from this generated object
    add_library(${MCSMEMA_RT32} STATIC ${MCSMEMA_RT32}.obj runtime_32.o)
    set_target_properties(${MCSMEMA_RT32} PROPERTIES STATIC_LIBRARY_FLAGS "/machine:x86")

    # add_library does not know how to link this thing together from an obj
    # tell cmake its just like C (the same command line will work for the object)
    set_target_properties(
      ${MCSMEMA_RT32} 
      PROPERTIES
      LINKER_LANGUAGE C
    )

    # use a custom step to build asm->obj since cmake wont recognize how to build our asm
    add_custom_command(
      OUTPUT ${MCSMEMA_RT32}.obj
      COMMAND "${CMAKE_C_COMPILER}" -m32 /Fo${MCSMEMA_RT32}.obj /c runtime_32.asm
      DEPENDS runtime_32.asm
      COMMENT "Building Runtime ASM..."
    )

    set_source_files_properties(
      ${MCSMEMA_RT32}.obj
      PROPERTIES
      EXTERNAL_OBJECT True
      GENERATED True
    )

    add_custom_command(
      OUTPUT runtime_32.asm
      COMMAND mcsema-print-runtime-x86
      DEPENDS mcsema-print-runtime-x86
      COMMENT "Generating 32-bit Windows PE runtime..."
    )
  
  elseif(UNIX)
    # Linux and friends
    add_compile_options(-Wno-invalid-offsetof)
    
    add_executable(mcsema-print-runtime-x86
      print_ELF_32_linux.cpp
    )

    # this is going to import the public include headers of remill
    target_link_libraries(mcsema-print-runtime-x86 PRIVATE remill)
    target_include_directories(mcsema-print-runtime-x86 PRIVATE
      "${REMILL_INCLUDE_LOCATION}" "${MCSEMA_SOURCE_DIR}"
    )

    add_library(${MCSMEMA_RT32} STATIC runtime_32.S runtime_32.o)
    set_target_properties(${MCSMEMA_RT32}
      PROPERTIES COMPILE_FLAGS "-m32 -fPIC" LINK_FLAGS "-m32 -fPIC"
    )

    add_custom_command(
      OUTPUT runtime_32.S
      COMMAND mcsema-print-runtime-x86
      DEPENDS mcsema-print-runtime-x86
      COMMENT "Generating 32-bit Linux ELF runtime..."
    )

  else()
    message(ERROR "Unsupported operating system")
  endif()

  install(
    TARGETS ${MCSMEMA_RT32}
    ARCHIVE DESTINATION "${install_folder}/lib"
  )
 
  # only do 64-bit binaries on 64-bit platforms
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    if(WIN32)
      add_executable(mcsema-print-runtime-amd64
        print_PE_64_windows.cpp
      )

      # this is going to import the public include headers of remill
      target_link_libraries(mcsema-print-runtime-amd64 PRIVATE remill)
      target_include_directories(mcsema-print-runtime-amd64 PRIVATE
        "${REMILL_INCLUDE_LOCATION}" "${MCSEMA_SOURCE_DIR}"
      )

      # build a static library from this generated object
      add_library(${MCSMEMA_RT64} STATIC ${MCSMEMA_RT64}.obj runtime_64.o)
      set_target_properties(${MCSMEMA_RT64} PROPERTIES STATIC_LIBRARY_FLAGS "/MACHINE:X64")

      # add_library does not know how to link this thing together from an obj
      # tell cmake its just like C (the same command line will work for the object)
      set_target_properties(
        ${MCSMEMA_RT64} 
        PROPERTIES
        LINKER_LANGUAGE C
      )

      # use a custom step to build asm->obj since cmake wont recognize how to build our asm
      add_custom_command(
        OUTPUT ${MCSMEMA_RT64}.obj
        COMMAND "${CMAKE_C_COMPILER}" -m64 /Fo${MCSMEMA_RT64}.obj /c runtime_64.asm
        DEPENDS runtime_64.asm
        COMMENT "Building Runtime ASM..."
      )

      set_source_files_properties(
        ${MCSMEMA_RT64}.obj
        PROPERTIES
        EXTERNAL_OBJECT True
        GENERATED True
      )

      add_custom_command(
        OUTPUT runtime_64.asm
        COMMAND mcsema-print-runtime-amd64
        DEPENDS mcsema-print-runtime-amd64
        COMMENT "Generating 64-bit Windows PE runtime..."
      )
    
    elseif(UNIX)
      add_compile_options(-Wno-invalid-offsetof)

      # Linux and friends
      add_executable(mcsema-print-runtime-amd64
        print_ELF_64_linux.cpp
      )

      # this is going to import the public include headers of remill
      target_link_libraries(mcsema-print-runtime-amd64 PRIVATE remill)

      target_include_directories(mcsema-print-runtime-amd64 PRIVATE
        "${REMILL_INCLUDE_LOCATION}" "${MCSEMA_SOURCE_DIR}"
      )

      add_library(${MCSMEMA_RT64} STATIC runtime_64.S runtime_64.o)
      set_target_properties(${MCSMEMA_RT64}
        PROPERTIES COMPILE_FLAGS "-m64 -fPIC" LINK_FLAGS "-m64 -fPIC"
      )

      add_custom_command(
        OUTPUT runtime_64.S
        COMMAND mcsema-print-runtime-amd64
        DEPENDS mcsema-print-runtime-amd64
        COMMENT "Generating 64-bit Linux ELF runtime..."
      )

    else()
      message(ERROR "Unsupported operating system")
    endif()

    install(
      TARGETS ${MCSMEMA_RT64}
      ARCHIVE DESTINATION "${install_folder}/lib"
    )
  endif()
endif()

# Create a runtime.
add_custom_command(
  OUTPUT runtime_32.o
  COMMAND "${CMAKE_CXX_COMPILER}" -std=gnu++11 -isystem "${REMILL_SOURCE_DIR}" -isystem "${MCSEMA_SOURCE_DIR}" -m32 -fPIC -c "${CMAKE_CURRENT_SOURCE_DIR}/Runtime.cpp" -o runtime_32.o
  DEPENDS Runtime.cpp
  COMMENT "Building 32-bit runtime"
)

set_source_files_properties(
  runtime_32.o
  PROPERTIES
  EXTERNAL_OBJECT True
  GENERATED True
)

# only do 64-bit binaries on 64-bit platforms
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  add_custom_command(
    OUTPUT runtime_64.o
    COMMAND "${CMAKE_CXX_COMPILER}" -std=gnu++11 -isystem "${REMILL_SOURCE_DIR}" -isystem "${MCSEMA_SOURCE_DIR}" -m64  -fPIC -c "${CMAKE_CURRENT_SOURCE_DIR}/Runtime.cpp" -o runtime_64.o
    DEPENDS Runtime.cpp
    COMMENT "Building 64-bit runtime"
  )
    
  set_source_files_properties(
    runtime_64.o
    PROPERTIES
    EXTERNAL_OBJECT True
    GENERATED True
  )
endif()

add_runtime(runtime_x86
  SOURCES "Runtime.cpp"
  ADDRESS_SIZE 32
  BCFLAGS  "-xc++" "-m32" "-std=gnu++17" "-Wno-deprecated-declarations"
  INCLUDEDIRECTORIES "${CMAKE_SOURCE_DIR}" "${MCSEMA_SOURCE_DIR}"
  INSTALLDESTINATION "${install_folder}/lib"
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  add_runtime(runtime_amd64
    SOURCES "Runtime.cpp"
    ADDRESS_SIZE 64
    BCFLAGS  "-xc++" "-m64" "-std=gnu++17" "-Wno-deprecated-declarations"
    INCLUDEDIRECTORIES "${CMAKE_SOURCE_DIR}" "${MCSEMA_SOURCE_DIR}"
    INSTALLDESTINATION "${install_folder}/lib"
  )
endif()
