#----------------------------------------------------------------------------
# This file was automatically generated from the original CMakeLists.txt file
# Add a variable to hold the headers for the library
set (lib_headers
    accumulators
)

# Add a library target to the build system
boost_library_project(
  accumulators
  TESTDIRS  test 
  EXAMPLEDIRS example
  HEADERS ${lib_headers}
  DOCDIRS doc
  DESCRIPTION  "A framework for incremental calculation, and a collection of statistical accumulators."
  MODULARIZED
  AUTHORS  "Eric Niebler <eric -at- boost-consulting.com>"
  #  MAINTAINERS 
)


