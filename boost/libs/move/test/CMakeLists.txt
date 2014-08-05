#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
boost_additional_test_dependencies (move BOOST_DEPENDS test)

#
set (TESTS
  doc_clone_ptr
  doc_construct_forward
  doc_file_descriptor
  doc_how_works
  doc_move_algorithms
  doc_move_inserter
  doc_move_iterator
)

foreach (_test ${TESTS})
  boost_test_run (${_test} DEPENDS boost_unit_test_framework)
endforeach (_test ${TESTS})

if (WIN32)
  message ("Need to turn on iterator debugging")
endif (WIN32)
