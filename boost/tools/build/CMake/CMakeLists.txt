#
# Copyright (C) Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
#   http://www.boost.org/LICENSE_1_0.txt
#
#
# On unix this is '/usr/share/cmake/boost'
#
set(BOOST_CMAKE_INFRASTRUCTURE_INSTALL_DIR
  "share/boost-${BOOST_VERSION}/cmake"
  CACHE STRING 
  "Directory to install Boost-${BOOST_VERSION} to")

#
# Provides version number to sphinx build
#
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/docs/source/boost_cmake_version.py.in
  ${CMAKE_CURRENT_SOURCE_DIR}/docs/source/boost_cmake_version.py)

#
# Makefile for sphinx build with maintainer targets
#
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/docs/Makefile.in
  ${CMAKE_CURRENT_SOURCE_DIR}/docs/Makefile)

#
# File used by BoostConfigVersion to import targets/libs/etc 
# into users's cmake build
#
foreach (file 
    BoostConfig
    BoostConfigVersion
    BoostConfigAgnostic
    BoostConfigVersionAgnostic)
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/install_me/${file}.cmake.in 
    ${CMAKE_CURRENT_SOURCE_DIR}/install_me/${file}.cmake @ONLY)
endforeach()


#
#  These are generated, version-specific
#
install(FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/install_me/BoostConfigVersion.cmake
  ${CMAKE_CURRENT_SOURCE_DIR}/install_me/BoostConfig.cmake
  DESTINATION ${BOOST_CMAKE_INFRASTRUCTURE_INSTALL_DIR}
  )

#
# The files that go in <prefix>/share/cmake/boost that search for
# Boost-<version>.cmake files (user specifies <version>)
#
option(BOOST_INSTALL_CMAKE_DRIVERS
  "Install version-agnostic BoostConfig.cmake and BoostConfigVersion.cmake to this subdirectory of CMAKE_INSTALL_PREFIX" ON)

if (BOOST_INSTALL_CMAKE_DRIVERS)
  if (NOT BOOST_CMAKE_DRIVERS_INSTALL_DIR)
    set(agnostic_infra_dir "share/cmake/boost")
  else()
    set(agnostic_infra_dir ${BOOST_CMAKE_DRIVERS_INSTALL_DIR})
  endif()
  install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/install_me/BoostConfigAgnostic.cmake
    DESTINATION ${agnostic_infra_dir}
    RENAME BoostConfig.cmake
    )
  install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/install_me/BoostConfigVersionAgnostic.cmake
    DESTINATION ${agnostic_infra_dir}
    RENAME BoostConfigVersion.cmake
    )
endif()


