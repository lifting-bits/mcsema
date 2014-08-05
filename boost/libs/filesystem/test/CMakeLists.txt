#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
boost_additional_test_dependencies (filesystem BOOST_DEPENDS test bind)

#
ADD_DEFINITIONS (-DBOOST_ALL_NO_LIB) # -DBOOST_FILESYSTEM_STATIC_LINK

#
boost_test_compile(mbcopy ../example/mbcopy.cpp)
boost_test_compile(mbpath ../example/mbpath.cpp)
boost_test_compile(tchar ../example/tchar.cpp)
boost_test_compile(file_size ../example/file_size.cpp)
boost_test_compile(path_info ../example/path_info.cpp)
boost_test_compile(error_demo ../example/error_demo.cpp)
boost_test_compile(tut0 ../example/tut0.cpp)
boost_test_compile(tut1 ../example/tut1.cpp)
boost_test_compile(tut2 ../example/tut2.cpp)
boost_test_compile(tut3 ../example/tut3.cpp)
boost_test_compile(tut4 ../example/tut4.cpp)
boost_test_compile(tut5 ../example/tut5.cpp)

#
SET (TESTS path_unit_test path_test
  operations_unit_test operations_test 
  fstream_test convenience_test 
  large_file_support_test deprecated_test
  simple_ls)

FOREACH (test ${TESTS})
  boost_test_run(${test}_static
    ${test}.cpp
    DEPENDS boost_filesystem STATIC
    COMPILE_FLAGS -DBOOST_FILESYSTEM_STATIC_LINK)
  boost_test_run(${test}_dynamic
    ${test}.cpp
    DEPENDS boost_filesystem SHARED
    COMPILE_FLAGS -DBOOST_FILESYSTEM_DYN_LINK)
ENDFOREACH (test ${TESTS})
