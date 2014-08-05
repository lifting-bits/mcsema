#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
# Add a variable to hold the headers for the library
set (lib_headers
    geometry
)

# Add a library target to the build system
boost_library_project(
  geometry
  TESTDIRS  test 
  EXAMPLEDIRS example
  HEADERS ${lib_headers}
  DOCDIRS doc
  DESCRIPTION  "Geometry Library."
  MODULARIZED
  AUTHORS  "Barend Gehrels <barend - at - xs4all.nl>"
           "Bruno Lalande <bruno.lalande - at - gmail.com>"
		   "Mateusz Loskot <mateusz - at - loskot.net>"
  #  MAINTAINERS 
)


