#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
# Add a variable to hold the headers for the library
set (lib_headers
  locale.hpp
  locale
)

# Add a library target to the build system
boost_library_project (
  locale
  SRCDIRS  src
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "Provide localization and Unicode handling tools for C++."
  MODULARIZED
  AUTHORS  "Vicente J. Botet Escribá <vicente.botet - at - wanadoo.fr>"
  #  MAINTAINERS 
)


