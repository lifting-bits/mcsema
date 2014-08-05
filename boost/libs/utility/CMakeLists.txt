#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
# Add a variable to hold the headers for the library
set (lib_headers
    assert.hpp
    call_traits.hpp
    checked_delete.hpp
    compressed_pair.hpp
    current_function.hpp
    operators.hpp
    throw_exception.hpp
    utility.hpp
    utility
)

# Add a library target to the build system
boost_library_project (utility
  #  SRCDIRS 
  TESTDIRS test enable_if/test identity_type/test swap/test
  HEADERS ${lib_headers}
  DOCDIRS doc identity_type/doc
  DESCRIPTION  "Various small utilities for C++ programming."
  MODULARIZED 
  AUTHORS  "David Abrahams <dave -at- boostpro.com>"
           "Brad King <brad.king -at- kitware.com>"
           "Douglas Gregor <doug.gregor -at- gmail.com>"
  #  MAINTAINERS 
)
