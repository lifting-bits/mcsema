#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
# Add a variable to hold the headers for the library
set (lib_headers
    algorithm
)

# Add a library target to the build system
boost_library_project (algorithm
  #  SRCDIRS
  TESTDIRS minmax/test string/test test
  EXAMPLEDIRS minmax/example string/example example
  HEADERS ${lib_headers}
  DOCDIRS doc 
  DESCRIPTION  "A collection of general purpose algorithms."
  MODULARIZED
  AUTHORS  "Marshall Clow <mclow.lists -at- gmail.com>"
  #  MAINTAINERS 
)
