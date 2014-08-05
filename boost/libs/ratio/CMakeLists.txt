#----------------------------------------------------------------------------
# This file was automatically generated from the original CMakeLists.txt file
# Add a variable to hold the headers for the library
set (lib_headers
    ratio
)

# Add a library target to the build system
boost_library_project(
  ratio
  TESTDIRS  test 
  EXAMPLEDIRS example
  HEADERS ${lib_headers}
  DOCDIRS doc
  DESCRIPTION  "Compile time rational arithmetic."
  MODULARIZED
  AUTHORS  "Vicente J. Botet Escribá <vicente.botet - at - wanadoo.fr>"
  #  MAINTAINERS 
)


