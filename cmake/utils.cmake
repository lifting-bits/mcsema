cmake_minimum_required(VERSION 3.2)

function(FindAndSelectClangCompiler)
  if(DEFINED ENV{LLVM_INSTALL_PREFIX})
    set(LLVM_INSTALL_PREFIX $ENV{LLVM_INSTALL_PREFIX} PARENT_SCOPE)
  endif()

  if(DEFINED LLVM_INSTALL_PREFIX)
    list(APPEND FINDPACKAGE_LLVM_HINTS "${LLVM_INSTALL_PREFIX}/lib/cmake/llvm/")
    list(APPEND FINDPACKAGE_LLVM_HINTS "${LLVM_INSTALL_PREFIX}/share/llvm/cmake/")
    set(FINDPACKAGE_LLVM_HINTS ${FINDPACKAGE_LLVM_HINTS} PARENT_SCOPE)

    message(STATUS "Using LLVM_INSTALL_PREFIX hints for find_package(LLVM): ${FINDPACKAGE_LLVM_HINTS}")
  endif()

  if(DEFINED WIN32)
    set(executable_extension ".exe")
  else()
    set(executable_extension "")
  endif()

  # it is important to avoid re-defining these variables if they have been already
  # set or you risk ending up in a configure loop!
  if(NOT DEFINED CMAKE_C_COMPILER)
    if(DEFINED LLVM_INSTALL_PREFIX)
      set(CMAKE_C_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang${executable_extension}"
        CACHE PATH "Path to clang binary." FORCE)
    else()
      set(CMAKE_C_COMPILER "clang" PARENT_SCOPE)
    endif()
  endif()

  if(NOT DEFINED CMAKE_CXX_COMPILER)
    if(DEFINED LLVM_INSTALL_PREFIX)
      set(CMAKE_CXX_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang++${executable_extension}"
        CACHE PATH "Path to clang++ binary." FORCE)
    else()
      set(CMAKE_CXX_COMPILER "clang++${executable_extension}" PARENT_SCOPE)
    endif()
  endif()

  if(NOT DEFINED CMAKE_ASM_COMPILER)
    if(DEFINED LLVM_INSTALL_PREFIX)
      set(CMAKE_ASM_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang++${executable_extension}"
        CACHE PATH "Path to assembler (aka clang) binary." FORCE)
    else()
      set(CMAKE_ASM_COMPILER ${CMAKE_CXX_COMPILER} PARENT_SCOPE)
    endif()
  endif()

  if(NOT DEFINED CMAKE_LLVM_LINK)
    if(DEFINED LLVM_INSTALL_PREFIX)
      set(CMAKE_LLVM_LINK "${LLVM_INSTALL_PREFIX}/bin/llvm-link${executable_extension}"
        CACHE PATH "Path to llvm-link binary." FORCE)
    else()
      set(CMAKE_LLVM_LINK "llvm-link${executable_extension}" PARENT_SCOPE)
    endif()
  endif()
endfunction()
