#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
# Add a variable to hold the headers for the library
set (lib_headers
    heap
)

# Add a library target to the build system
boost_library_project (heap
  TESTDIRS test
  EXAMPLEDIRS examples
  HEADERS ${lib_headers}
  DOCDIRS doc
  DESCRIPTION  "An implementation of priority queues."
  MODULARIZED
  AUTHORS  "Tim Blechmann <tim - at - klingt.org>"
  #  MAINTAINERS 
)


