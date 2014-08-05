#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on http://github.com/pocb/boost
#----------------------------------------------------------------------------
#
# Add a variable to hold the headers for the library
set (lib_headers
    timer.hpp
)

# Add a library target to the build system
boost_library_project (
  timer
  SRCDIRS  src
  TESTDIRS  test
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "The timer library calculates how long C++ code takes to run."
  MODULARIZED 
  AUTHORS  "Beman Dawes <bdawes - at - acm.org>"
  #  MAINTAINERS 
)


