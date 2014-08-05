#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
# Add a variable to hold the headers for the library
set (lib_headers
    container
)

# Add a library target to the build system
boost_library_project (container
  TESTDIRS  test
  EXAMPLEDIRS example
  HEADERS ${lib_headers}
  DOCDIRS doc
  DESCRIPTION  "Standard library containers and extensions."
  MODULARIZED
  AUTHORS  "Ion Gaztañaga <igaztanaga - at - gmail.com>"
  #  MAINTAINERS 
)


