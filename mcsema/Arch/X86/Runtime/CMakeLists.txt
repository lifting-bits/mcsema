# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.
enable_language(ASM)

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
    set_target_properties(mcsema-print-runtime-x86
      PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "/MACHINE:X86")

    # build a static library from this generated object
    add_library(mcsema_rt32 STATIC mcsema_rt32.obj)
    # add_library does not know how to link this thing together from an obj
    # tell cmake its just like C (the same command line will work for the object)
    set_target_properties(
      mcsema_rt32 
      PROPERTIES
      LINKER_LANGUAGE C)

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
    add_executable(mcsema-print-runtime-x86
      print_ELF_32_linux.cpp)
    set_target_properties(mcsema-print-runtime-x86
      PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")

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
      set_target_properties(mcsema-print-runtime-amd64
        PROPERTIES COMPILE_FLAGS "-m64" LINK_FLAGS "/MACHINE:X64")

      # build a static library from this generated object
      add_library(mcsema_rt64 STATIC mcsema_rt64.obj)
      # add_library does not know how to link this thing together from an obj
      # tell cmake its just like C (the same command line will work for the object)
      set_target_properties(
        mcsema_rt64 
        PROPERTIES
        LINKER_LANGUAGE C)

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
      # Linux and friends
      add_executable(mcsema-print-runtime-amd64
        print_ELF_64_linux.cpp)
      set_target_properties(mcsema-print-runtime-amd64
        PROPERTIES COMPILE_FLAGS "-m64" LINK_FLAGS "-m64")

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

