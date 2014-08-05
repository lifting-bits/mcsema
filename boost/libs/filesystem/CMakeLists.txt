#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
# Add a variable to hold the headers for the library
set (lib_headers
  filesystem.hpp
  filesystem
)

# Add a library target to the build system
boost_library_project (filesystem
  SRCDIRS src
  TESTDIRS test
  HEADERS ${lib_headers}
  DOCDIRS doc
  DESCRIPTION  "Provides portable facilities to query and manipulate paths, files, and directories. Note: the default version is now v3: v2 is no longer distributed."
  MODULARIZED
  AUTHORS  "Beman Dawes <bdawes -at- acm.org>"
  #  MAINTAINERS 
  )
