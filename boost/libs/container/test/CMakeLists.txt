#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
boost_additional_test_dependencies (container BOOST_DEPENDS test)

#
set (TESTS
  deque_test
  flat_tree_test
  list_test
  slist_test
  stable_vector_test
  string_test
  tree_test
  vector_test)

foreach (_test ${TESTS})
  boost_test_run (${_test} DEPENDS boost_unit_test_framework)
endforeach (_test ${TESTS})

if (WIN32)
  message ("Need to turn on iterator debugging")
endif (WIN32)
