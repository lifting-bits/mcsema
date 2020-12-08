set(USE_SYSTEM_DEPENDENCIES OFF CACHE BOOL "Use system dependencies instead of trying to find vcpkg")

if (NOT USE_SYSTEM_DEPENDENCIES)
  set(VCPKG_ROOT "" CACHE FILEPATH "Root directory to use for vcpkg-managed dependencies")
  if (VCPKG_ROOT)
    if (NOT EXISTS "${VCPKG_ROOT}")
      message(FATAL_ERROR "VCPKG_ROOT directory does not exist: '${VCPKG_ROOT}'")
    endif()

    set(VCPKG_ROOT_INSTALL_DIR "${VCPKG_ROOT}/installed")
    if (NOT EXISTS "${VCPKG_ROOT_INSTALL_DIR}")
      message(FATAL_ERROR "VCPKG_ROOT installation directory does not exist: '${VCPKG_ROOT_INSTALL_DIR}'")
    endif()

    set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE FILEPATH "" FORCE)
  else()
    message(FATAL_ERROR "Please define a path to VCPKG_ROOT. See https://github.com/trailofbits/cxx-common for more details. Or if you don't want to use vcpkg dependencies, add '-DUSE_SYSTEM_DEPENDENCIES=ON'")
  endif()

  # Set default triplet to Release VCPKG build unless we can't find it
  if (NOT DEFINED VCPKG_TARGET_TRIPLET)
    if (APPLE)
      set(_project_vcpkg_triplet "x64-osx-rel")
    elseif(UNIX)
      set(_project_vcpkg_triplet "x64-linux-rel")
    else()
      message(FATAL_ERROR "Could not detect default release triplet")
    endif()

    if (NOT EXISTS "${VCPKG_ROOT_INSTALL_DIR}/${_project_vcpkg_triplet}")
      message(STATUS "Could not find installed project-default triplet '${_project_vcpkg_triplet}' using vcpkg-default for your system")
    else()
      set(VCPKG_TARGET_TRIPLET "${_project_vcpkg_triplet}" CACHE STRING "")
      message(STATUS "Setting default vcpkg triplet to release-only libraries: ${VCPKG_TARGET_TRIPLET}")
    endif()
  endif()

  if (DEFINED VCPKG_TARGET_TRIPLET AND NOT EXISTS "${VCPKG_ROOT_INSTALL_DIR}/${VCPKG_TARGET_TRIPLET}")
    message(FATAL_ERROR "Could not find vcpkg triplet (${VCPKG_TARGET_TRIPLET}) installation libraries '${VCPKG_ROOT_INSTALL_DIR}/${VCPKG_TARGET_TRIPLET}'.")
  endif()

  message(STATUS "Using vcpkg installation directory at '${VCPKG_ROOT_INSTALL_DIR}/${VCPKG_TARGET_TRIPLET}'")
endif()
