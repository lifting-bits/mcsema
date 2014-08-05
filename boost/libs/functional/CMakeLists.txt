#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
# Add a variable to hold the headers for the library
set (lib_headers
    functional.hpp
    functional
)

# Add a library target to the build system
boost_library_project (functional
  #  SRCDIRS 
  TESTDIRS test hash/test
  EXAMPLEDIRS hash/examples
  HEADERS ${lib_headers}
  DOCDIRS  factory/doc forward/doc hash/doc overloaded_function/doc
  DESCRIPTION "Various functional-related components: Factory, Forward Adapter, Hash and Overloaded Function"
  MODULARIZED 
  AUTHORS  "Lorenzo Caminiti <lorcaminiti - at - gmail.com> for Overloaded Function"
  #  MAINTAINERS 
)


