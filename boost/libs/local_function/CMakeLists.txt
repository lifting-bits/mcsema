#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
# Add a variable to hold the headers for the library
set (lib_headers
    local_function.hpp
    local_function
)

# Add a library target to the build system
boost_library_project (local_function
  #  SRCDIRS 
  TESTDIRS test
  EXAMPLEDIRS example
  HEADERS ${lib_headers}
  DOCDIRS  doc
  DESCRIPTION "Various functional-related components: Factory, Forward Adapter, Hash and Overloaded Function"
  MODULARIZED 
  AUTHORS  "Lorenzo Caminiti <lorcaminiti - at - gmail.com> for Overloaded Function"
  #  MAINTAINERS 
)


