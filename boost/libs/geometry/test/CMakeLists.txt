#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
boost_additional_test_dependencies (geometry BOOST_DEPENDS test)

#
set (TESTS 
  core
  point_concept 
  geometries
  arithmetic
  algorithms
  iterators
  strategies
  policies
  util
  views
  multi
  domains)

foreach (_test ${TESTS})
  boost_test_run (${_test} DEPENDS boost_unit_test_framework)
endforeach (_test ${TESTS})

if (WIN32)
  message ("Need to turn on iterator debugging")
endif (WIN32)
