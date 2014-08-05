#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
# Add a variable to hold the headers for the library
set (lib_headers
  context
)

# Add a library target to the build system
boost_library_project (
  context
  SRCDIRS  src
  TESTDIRS  test
  HEADERS ${lib_headers}
  DOCDIRS doc
  EXAMPLEDIRS example
  DESCRIPTION  "A sort of cooperative multitasking on a single thread."
  MODULARIZED
  AUTHORS  "Oliver Kowalke <oliver.kowalke - at - gmail.com>"
  #  MAINTAINERS 
)

