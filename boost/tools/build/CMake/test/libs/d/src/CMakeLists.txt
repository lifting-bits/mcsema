#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#

foreach(feature STATIC SHARED SINGLE_THREADED MULTI_THREADED
    DEBUG RELEASE)
  boost_add_library(d_no_${feature}
    lib.cpp
    NO_${feature}
    )
endforeach()


#
# Each of these never builds as it depends on something that
# doesn't exist
#
boost_add_library(no_shared
  lib.cpp
  NO_SHARED
  DEPENDS boost_d_no_STATIC)
 
boost_add_library(no_static
  lib.cpp
  NO_STATIC
  DEPENDS boost_d_no_SHARED)

boost_add_library(no_debug
  lib.cpp
  NO_DEBUG
  DEPENDS boost_d_no_RELEASE)

boost_add_library(no_release
  lib.cpp
  NO_RELEASE
  DEPENDS boost_d_no_DEBUG)
 
boost_add_library(no_multi
  lib.cpp
  NO_MULTI_THREADED
  DEPENDS boost_d_no_SINGLE_THREADED)

boost_add_library(no_single
  lib.cpp
  NO_MULTI_THREADED
  DEPENDS boost_d_no_SINGLE_THREADED)

#
# Problem:  You can pass NO_MULTI_THREADED to this
# and get something that never builds
#
boost_python_extension(doesntbuild
  lib.cpp
  NO_MULTI_THREADED
  DEPENDS boost_d_no_SINGLE_THREADED)

