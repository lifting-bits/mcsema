#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
# Add a variable to hold the headers for the library
set (lib_headers
  move
)

# Add a library target to the build system
boost_library_project (move
  TESTDIRS  test
  EXAMPLEDIRS example
  HEADERS ${lib_headers}
  DOCDIRS doc
  DESCRIPTION  "Portable move semantics for C++03 and C++11 compilers."
  MODULARIZED
  AUTHORS  "Ion Gaztañaga <igaztanaga - at - gmail.com>"
  #  MAINTAINERS 
)


