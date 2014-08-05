#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
#----------------------------------------------------------------------------
# This file was automatically generated from the original CMakeLists.txt file
# Add a variable to hold the headers for the library
set (lib_headers
    type_traits.hpp
    type_traits
)

# Add a library target to the build system
boost_library_project(
  type_traits
  #  SRCDIRS 
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "Templates for fundamental properties of types."
  MODULARIZED 
  AUTHORS  "David Abrahams <dave -at- boostpro.com>"
           "Steve Cleary" 
           "Beman Dawes <bdawes -at- acm.org>" 
           "Aleksey Gurtovoy <agurtovoy -at- meta-comm.com>" 
           "Howard Hinnant" 
           "Jesse Jones" 
           "Mat Marcus" 
           "Itay Maman" 
           "John Maddock <john -at- johnmaddock.co.uk>" 
           "Alexander Nasonov <alexander.nasonov -at- gmail.com>" 
           "Thorsten Ottosen <nesotto -at- cs.auc.dk>"
           "Robert Ramey <ramey -at- rrsd.com>" 
           "Jeremy Siek <jeremy.siek -at- gmail.com>"
  #  MAINTAINERS 
)


