#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
# Add a variable to hold the headers for the library
set (lib_headers
    chrono.hpp
    chrono
)

# Add a library target to the build system
boost_library_project(
  chrono
  SRCDIRS  src
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "Useful time utilities."
  MODULARIZED
  AUTHORS  "Vicente J. Botet Escribá <vicente.botet - at - wanadoo.fr>"
  #  MAINTAINERS 
)


