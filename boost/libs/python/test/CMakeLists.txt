#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
include_directories(${PYTHON_INCLUDE_PATH})

macro(bpl_test TESTNAME)
  parse_arguments(BPL_TEST
    "ARGS"
    ""
    ${ARGN})

  # Determine the Python and C++ source files for this test
  if (BPL_TEST_DEFAULT_ARGS)
    # First argument is the Python source we will run, the rest are
    # either extra Python sources we're dependent on or C++ files from
    # which we will build extension modules.
    car(BPL_TEST_PYSOURCE ${BPL_TEST_DEFAULT_ARGS})
    cdr(BPL_TEST_DEFAULT_ARGS ${BPL_TEST_DEFAULT_ARGS})

    get_filename_component(BPL_TEST_PYBASE ${BPL_TEST_PYSOURCE} NAME_WE)

    # Process all the .cpp file and extension module names
    foreach(SRC ${BPL_TEST_DEFAULT_ARGS})
      get_filename_component(BPL_SRC_EXT ${SRC} EXT)
      if (BPL_SRC_EXT STREQUAL ".cpp")

        # Build a Python extension module from this source file
        get_filename_component(BPL_SRC_NAME ${SRC} NAME_WE)
        
        if(BPL_TEST_PYBASE STREQUAL "${BPL_SRC_NAME}")
          set(BPL_EXTENSION_MODULE ${BPL_SRC_NAME}_ext)
        else(BPL_TEST_PYBASE STREQUAL "${BPL_SRC_NAME}")
          set(BPL_EXTENSION_MODULE ${BPL_SRC_NAME})
        endif(BPL_TEST_PYBASE STREQUAL "${BPL_SRC_NAME}")

        boost_python_extension(${BPL_EXTENSION_MODULE} ${SRC})

      else (BPL_SRC_EXT STREQUAL ".cpp")
        set(BPL_EXTENSION_MODULE ${SRC})

      endif (BPL_SRC_EXT STREQUAL ".cpp")

    endforeach(SRC ${BPL_TEST_DEFAULT_ARGS})

  else (BPL_TEST_DEFAULT_ARGS)

    set(BPL_TEST_PYSOURCE "${TESTNAME}.py")

    # Build a Python extension module from this source file
    boost_python_extension(${TESTNAME}_ext "${TESTNAME}.cpp")

  endif(BPL_TEST_DEFAULT_ARGS)

  # We'll need the full patch to run the Python test
  set(BPL_TEST_PYSOURCE ${CMAKE_CURRENT_SOURCE_DIR}/${BPL_TEST_PYSOURCE})
    
  # Run the test itself

  if(WIN32)

    get_target_property(THIS_TEST_LOCATION ${TESTNAME}_ext-mt-shared
      LOCATION)
    get_filename_component(THIS_TEST_LOCATION ${THIS_TEST_LOCATION} PATH)

    string(REGEX REPLACE "\\$\\(.*\\)" "\${CTEST_CONFIGURATION_TYPE}"
      THIS_TEST_LOCATION "${THIS_TEST_LOCATION}")

    set(PYTHONPATH ${THIS_TEST_LOCATION})
  else()
    file(TO_NATIVE_PATH "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}" PYTHONPATH)
  endif()
  
  if(WIN32 AND NOT UNIX)
    string(REPLACE "\\" "\\\\" PYTHONPATH "${PYTHONPATH}")
  endif(WIN32 AND NOT UNIX)
  set(FULL_TESTNAME ${PROJECT_NAME}-${TESTNAME})
  add_test(${FULL_TESTNAME}
    ${VALGRIND_EXECUTABLE}
    ${VALGRIND_FLAGS}
    ${PYTHON_EXECUTABLE} 
    "${CMAKE_CURRENT_SOURCE_DIR}/pyrun.py" 
    "${PYTHONPATH}"
    ${BPL_TEST_PYSOURCE} ${BPL_TEST_ARGS})

  set_tests_properties(${FULL_TESTNAME}
    PROPERTIES
    LABELS "${PROJECT_NAME}"
    )
endmacro(bpl_test)

macro(py_run TESTNAME)
  boost_test_run(${TESTNAME} 
    ${TESTNAME}.cpp
    DEPENDS boost_python STATIC
    LINK_LIBS ${PYTHON_LIBRARIES})
endmacro(py_run)

boost_test_run(exec 
  DEPENDS boost_python STATIC 
  ARGS "${CMAKE_CURRENT_SOURCE_DIR}/exec.py"
  LINK_LIBS ${PYTHON_LIBRARIES})
boost_test_run(exec-dynamic 
  exec.cpp
  ARGS "${CMAKE_CURRENT_SOURCE_DIR}/exec.py"
  DEPENDS boost_python SHARED 
  LINK_LIBS ${PYTHON_LIBRARIES})

bpl_test(crossmod_exception 
  crossmod_exception.py crossmod_exception_a.cpp crossmod_exception_b.cpp)

bpl_test(injected)
bpl_test(properties)
bpl_test(return_arg)
bpl_test(staticmethod)
bpl_test(shared_ptr)
bpl_test(andreas_beyer)
bpl_test(polymorphism)
bpl_test(polymorphism2)

bpl_test(wrapper_held_type)
bpl_test(polymorphism2_auto_ptr)

bpl_test(auto_ptr)

bpl_test(minimal)
bpl_test(args)
bpl_test(raw_ctor)
bpl_test(numpy numpy.py printer.py numeric_tests.py numarray_tests.py numpy.cpp)
bpl_test(enum)
bpl_test(exception_translator)
bpl_test(pearu1 test_cltree.py cltree.cpp)
bpl_test(try newtest.py m1.cpp m2.cpp)
bpl_test(const_argument)
bpl_test(keywords keywords_test.py keywords.cpp)
   
boost_python_extension(builtin_converters_ext test_builtin_converters.cpp)
bpl_test(builtin_converters test_builtin_converters.py builtin_converters_ext)

#
#   See the contents of this file for more details on an existing
#   overload resoluton bug.
#
#   boost_python_extension(overload_resolution test_overload_resolution.cpp)
#

bpl_test(test_pointer_adoption)
bpl_test(operators)
bpl_test(callbacks)
bpl_test(defaults)

bpl_test(object)
bpl_test(list)
bpl_test(long)
bpl_test(dict)
bpl_test(str)
bpl_test(slice)

bpl_test(virtual_functions)
bpl_test(back_reference)
bpl_test(implicit)
bpl_test(data_members)

bpl_test(ben_scott1)

bpl_test(bienstman1)
bpl_test(bienstman2)
bpl_test(bienstman3)

bpl_test(multi_arg_constructor)
# TODO: A bug in the Win32 intel compilers causes compilation of one
# of our tests to take forever when debug symbols are
# enabled. This rule turns them off when added to the requirements
# section 
#   <toolset>intel-win:<debug-symbols>off

bpl_test(iterator iterator.py iterator.cpp input_iterator.cpp)

bpl_test(stl_iterator stl_iterator.py stl_iterator.cpp)

bpl_test(extract)

bpl_test (crossmod_opaque
  crossmod_opaque.py crossmod_opaque_a.cpp crossmod_opaque_b.cpp)

bpl_test(opaque)
bpl_test(voidptr)

bpl_test(pickle1)
bpl_test(pickle2)
bpl_test(pickle3)
bpl_test(pickle4)

bpl_test(nested)

bpl_test(docstring)

bpl_test(vector_indexing_suite)

bpl_test(pointer_vector)
# TODO: Turn off this test on HP CXX, as the test hangs when executing.
# Whenever the cause for the failure of the polymorphism test is found
# and fixed, this should be retested.
#    <toolset>hp_cxx:<build>no
      
boost_python_extension(map_indexing_suite_ext 
  map_indexing_suite.cpp int_map_indexing_suite.cpp a_map_indexing_suite.cpp)

bpl_test(map_indexing_suite 
  map_indexing_suite.py map_indexing_suite_ext)


# --- unit tests of library components ---

boost_test_compile(indirect_traits_test)
boost_test_run(destroy_test)
py_run(pointer_type_id_test)
py_run(bases)
boost_test_run(if_else)
py_run(pointee)
boost_test_run(result)

boost_test_compile(string_literal)
boost_test_compile(borrowed)
boost_test_compile(object_manager)
boost_test_compile(copy_ctor_mutates_rhs)

py_run(upcast)
  
boost_test_compile(select_holder)

boost_test_run(select_from_python_test
  select_from_python_test.cpp ../src/converter/type_id.cpp
  COMPILE_FLAGS "-DBOOST_PYTHON_STATIC_LIB"
  LINK_LIBS ${PYTHON_LIBRARIES})
  
boost_test_compile(select_arg_to_python_test)

boost_test_compile_fail(raw_pyobject_fail1)
boost_test_compile_fail(raw_pyobject_fail2)
boost_test_compile_fail(as_to_python_function)
boost_test_compile_fail(object_fail1)

bpl_test(tuple)
