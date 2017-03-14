# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

enable_language(ASM)

# Create the Windows runtimes
if(WIN32)
  set(ASM_SUFFIX asm)
  add_executable(mcsema-print-runtime-x86
    ${MCSEMA_DIR}/mcsema/Arch/X86/Runtime/print_PE_32_windows.cpp)
  
  add_executable(mcsema-print-runtime-amd64
    ${MCSEMA_DIR}/mcsema/Arch/X86/Runtime/print_PE_64_windows.cpp)

# Create the Linux runtimes
else()

  add_executable(mcsema-print-runtime-x86
    ${MCSEMA_DIR}/mcsema/Arch/X86/Runtime/print_ELF_32_linux.cpp)
  
  add_executable(mcsema-print-runtime-amd64
    ${MCSEMA_DIR}/mcsema/Arch/X86/Runtime/print_ELF_64_linux.cpp)

  add_library(runtime_64 OBJECT
    ${MCSEMA_BUILD_DIR}/mcsema/Arch/X86/Runtime/runtime_64.S)
  
  add_library(runtime_32 OBJECT
    ${MCSEMA_BUILD_DIR}/mcsema/Arch/X86/Runtime/runtime_32.S)
    
  add_library(mcsema_rt64 STATIC $<TARGET_OBJECTS:runtime_64>)
  add_library(mcsema_rt32 STATIC $<TARGET_OBJECTS:runtime_32>)

  set_target_properties(runtime_32
    PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
  set_target_properties(mcsema_rt32
    PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")

  add_custom_target(runtime_32.S
    COMMAND mcsema-print-runtime-x86
    DEPENDS mcsema-print-runtime-x86)

  add_custom_target(runtime_64.S
    COMMAND mcsema-print-runtime-amd64
    DEPENDS mcsema-print-runtime-amd64)

  add_dependencies(runtime mcsema_rt64 mcsema_rt32)

endif(WIN32)

install(
  TARGETS mcsema_rt64 mcsema_rt32
  ARCHIVE DESTINATION lib)


  # add_custom_target(runtime_32.o
  #   COMMAND ${CMAKE_CXX_COMPILER}
  #           -fPIC
  #           -c ${MCSEMA_BUILD_DIR}/mcsema/Arch/X86/Runtime/runtime_32.S
  #           -o runtime_32.o
  #           -m32
  #   DEPENDS runtime_32.S)
  # 
  # add_custom_target(runtime_64.o
  #   COMMAND ${CMAKE_CXX_COMPILER}
  #           -fPIC
  #           -c ${MCSEMA_BUILD_DIR}/mcsema/Arch/X86/Runtime/runtime_64.S
  #           -o runtime_64.o
  #           -m64
  #   DEPENDS runtime_64.S)
  #   libmcsema_rt32.a
  #   libmcsema_rt64.a)

  # install(
  #     FILES libmcsema_rt32.so libmcsema_rt64.so
  #     DESTINATION lib)