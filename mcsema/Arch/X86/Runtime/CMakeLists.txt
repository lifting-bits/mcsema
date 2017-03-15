# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.
enable_language(ASM)

# Create the Windows runtimes
if(WIN32)

    #TODO(artem): find clang for windows compiler and build

# Create the Linux runtimes
else()

  add_executable(mcsema-print-runtime-x86
    print_ELF_32_linux.cpp)
  set_target_properties(mcsema-print-runtime-x86
    PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
 
  add_executable(mcsema-print-runtime-amd64
    print_ELF_64_linux.cpp)
  set_target_properties(mcsema-print-runtime-amd64
    PROPERTIES COMPILE_FLAGS "-m64" LINK_FLAGS "-m64")

  add_library(mcsema_rt64 STATIC
    runtime_64.S)
  set_target_properties(mcsema_rt64
    PROPERTIES COMPILE_FLAGS "-m64" LINK_FLAGS "-m64")

  add_library(mcsema_rt32 STATIC
    runtime_32.S)
  set_target_properties(mcsema_rt32
    PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")

  add_custom_command(
    OUTPUT runtime_32.S
    COMMAND mcsema-print-runtime-x86
    DEPENDS mcsema-print-runtime-x86
    COMMENT "Generating 32-bit runtime...")

  add_custom_command(
    OUTPUT runtime_64.S
    COMMAND mcsema-print-runtime-amd64
    DEPENDS mcsema-print-runtime-amd64
    COMMENT "Generating 64-bit runtime...")

  install(
    TARGETS mcsema_rt64 mcsema_rt32
    ARCHIVE DESTINATION lib)

endif(WIN32)

