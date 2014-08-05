#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(optional BOOST_DEPENDS test timer)


boost_test_run(basics)
boost_test_run(sfinae)
boost_test_run(macros)
boost_test_run(earwicker)
boost_test_run(tutorial)
boost_test_run(singular)
boost_test_run(mpl)
boost_test_run(preprocessor)
boost_test_run(preprocessor_deduced)
boost_test_run(efficiency COMPILE_FLAGS "${RELEASE_COMPILE_FLAGS}")
boost_test_run(maybe)
boost_test_run(deduced)
boost_test_run(optional_deduced_sfinae)
boost_test_run(deduced_dependent_predicate)
boost_test_run(normalized_argument_types)
boost_test_compile(ntp)
boost_test_compile(unwrap_cv_reference)
boost_test_compile_fail(duplicates)
boost_test_compile_fail(deduced_unmatched_arg)
boost_test_compile(compose)

if (PYTHON_FOUND)

  include_directories(${PYTHON_INCLUDE_PATH})

  #
  # This came from libs/python/test/CMakeLists.txt
  # 
  # copy-pasting this kind of code is of course an awful idea.
  #
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
    file(TO_NATIVE_PATH "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}" PYTHONPATH)
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

  bpl_test(python_test)

endif()