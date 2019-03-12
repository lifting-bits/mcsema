# This is only executed once; use a macro (and not a function) so that
# everything defined here does not end up in a separate namespace
macro(main)
  # default build type
  if(WIN32)
    set(CMAKE_BUILD_TYPE Release)
  else()
    if(NOT CMAKE_BUILD_TYPE)
      set(CMAKE_BUILD_TYPE "RelWithDebInfo")
    endif()
  endif()

  # overwrite the default install prefix
  if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    if(DEFINED WIN32)
      set(CMAKE_INSTALL_PREFIX "C:/")
    else()
      set(CMAKE_INSTALL_PREFIX "/usr/local")
    endif()
  endif()

  message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")

  # generate a compile commands JSON file.
  set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

  #
  # cxx-common
  #

  if(DEFINED ENV{TRAILOFBITS_LIBRARIES})
    set(LIBRARY_REPOSITORY_ROOT $ENV{TRAILOFBITS_LIBRARIES}
      CACHE PATH "Location of cxx-common libraries."
    )
  endif()

  if(DEFINED LIBRARY_REPOSITORY_ROOT)
    set(TOB_CMAKE_INCLUDE "${LIBRARY_REPOSITORY_ROOT}/cmake_modules/repository.cmake")
    if(NOT EXISTS "${TOB_CMAKE_INCLUDE}")
      message(FATAL_ERROR "The library repository could not be found!")
    endif()

    include("${TOB_CMAKE_INCLUDE}")

  else()
    message(STATUS "Using system libraries")
  endif()

  #
  # compiler and linker flags
  #

  # Globally set the required C++ standard
  if(WIN32)
    set(CMAKE_CXX_STANDARD 14)
  else()
    set(CMAKE_CXX_STANDARD 11)
  endif()

  set(CMAKE_CXX_EXTENSIONS OFF)

  if(WIN32)
    # warnings and compiler settings
    set(GLOBAL_CXXFLAGS
      /MD /nologo /W3 /EHsc /wd4141 /wd4146 /wd4180 /wd4244
      /wd4258 /wd4267 /wd4291 /wd4345 /wd4351 /wd4355 /wd4456
      /wd4457 /wd4458 /wd4459 /wd4503 /wd4624 /wd4722 /wd4800
      /wd4100 /wd4127 /wd4512 /wd4505 /wd4610 /wd4510 /wd4702
      /wd4245 /wd4706 /wd4310 /wd4701 /wd4703 /wd4389 /wd4611
      /wd4805 /wd4204 /wd4577 /wd4091 /wd4592 /wd4324
    )

    set(GLOBAL_DEFINITIONS
      _CRT_SECURE_NO_DEPRECATE
      _CRT_SECURE_NO_WARNINGS
      _CRT_NONSTDC_NO_DEPRECATE
      _CRT_NONSTDC_NO_WARNINGS
      _SCL_SECURE_NO_DEPRECATE
      _SCL_SECURE_NO_WARNINGS
      GOOGLE_PROTOBUF_NO_RTTI
    )

  else()
    # warnings and compiler settings
    set(GLOBAL_CXXFLAGS
      -Wall -Wextra -Wno-unused-parameter -Wno-c++98-compat
      -Wno-unreachable-code-return -Wno-nested-anon-types
      -Wno-extended-offsetof
      -Wno-variadic-macros -Wno-return-type-c-linkage
      -Wno-c99-extensions -Wno-ignored-attributes -Wno-unused-local-typedef
      -Wno-unknown-pragmas -Wno-unknown-warning-option -fPIC
      -fno-omit-frame-pointer -fvisibility-inlines-hidden -fno-exceptions
      -fno-asynchronous-unwind-tables
    )
    
    if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
      set(GLOBAL_CXXFLAGS
        ${GLOBAL_CXXFLAGS}
        -Wgnu-alignof-expression -Wno-gnu-anonymous-struct -Wno-gnu-designator
        -Wno-gnu-zero-variadic-macro-arguments -Wno-gnu-statement-expression
      )
    endif()

    # debug symbols
    if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
      list(APPEND GLOBAL_CXXFLAGS
        -gdwarf-2 -g3
      )
    endif()

    # optimization flags and definitions
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
      list(APPEND GLOBAL_CXXFLAGS -O0)
      list(APPEND PROJECT_DEFINITIONS "DEBUG")
    else()
      list(APPEND GLOBAL_CXXFLAGS -O3)
      list(APPEND PROJECT_DEFINITIONS "NDEBUG")
    endif()
  endif()

  if(UNIX)
    if(APPLE)
      set(PLATFORM_NAME "macos")
    else()
      set(PLATFORM_NAME "linux")
    endif()
  
  elseif(WIN32)
    set(PLATFORM_NAME "windows")

  else()
    message("This platform is not officially supported")
  endif()

  set(SETTINGS_CMAKE_ true)
endmacro()

if(NOT DEFINED SETTINGS_CMAKE_)
  main()
endif()
