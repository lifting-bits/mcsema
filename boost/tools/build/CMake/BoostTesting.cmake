##########################################################################
# Regression Testing Support for Boost                                   #
##########################################################################
# Copyright (C) 2007-8 Douglas Gregor <doug.gregor@gmail.com>            #
# Copyright (C) 2007-8 Troy D. Straszheim                                #
#                                                                        #
# Distributed under the Boost Software License, Version 1.0.             #
# See accompanying file LICENSE_1_0.txt or copy at                       #
#   http://www.boost.org/LICENSE_1_0.txt                                 #
##########################################################################
# This file provides a set of CMake macros that support regression
# testing for Boost libraries. For each of the test macros below, the
# first argument, testname, states the name of the test that will be
# created. If no other arguments are provided, the source file
# testname.cpp will be used as the source file; otherwise, source
# files should be listed immediately after the name of the test.
#
# The macros for creating regression tests are:
#   boost_test_run: Builds an executable and runs it as a test. The test
#                   succeeds if it builds and returns 0 when executed.
#
#   boost_test_run_fail: Builds an executable and runs it as a test. The
#                        test succeeds if it builds but returns a non-zero
#                        exit code when executed.
#  
#   boost_test_compile: Tests that the given source file compiles without 
#                       any errors.
#
#   boost_test_compile_fail: Tests that the given source file produces 
#                            errors when compiled.
#
#   boost_additional_test_dependencies: Adds needed include directories for
#                                       the tests.

# User-controlled option that can be used to enable/disable regression
# testing. By default, we disable testing, because most users won't
# want or need to perform regression testing on Boost. The Boost build
# is significantly faster when we aren't also building regression
# tests.

if (BOOST_CMAKE_SELFTEST)
  set(tests "ALL")
else()
  set(tests "NONE")
endif()

set(BUILD_TESTS ${tests} CACHE STRING "Semicolon-separated list of lowercase librarary names to test, or \"ALL\"")
enable_testing()

if (BUILD_TESTING)
  if (NOT EXISTS ${CMAKE_BINARY_DIR}/CTestCustom.cmake)
    configure_file(${CMAKE_SOURCE_DIR}/tools/build/CMake/CTestCustom.cmake.in
      ${CMAKE_BINARY_DIR}/CTestCustom.cmake
      COPYONLY)
  endif()
  include(CTest)
endif()

if (BUILD_TESTS STREQUAL "NONE")
  #
  # Add a little "message" if tests are run while BUILD_TESTS is NONE
  #
  add_test(BUILD_TESTS_is_NONE_nothing_to_test
    /bin/false)
endif()
 
set(DART_TESTING_TIMEOUT 15 
  CACHE INTEGER 
  "Timeout after this many seconds of madness")

#-------------------------------------------------------------------------------
# This macro adds additional include directories based on the dependencies of 
# the library being tested 'libname' and all of its dependencies.
#
#   boost_additional_test_dependencies(libname 
#                         BOOST_DEPENDS libdepend1 libdepend2 ...)
#
#   libname is the name of the boost library being tested. (signals)
#
# There is mandatory argument to the macro: 
#
#   BOOST_DEPENDS: The list of the extra boost libraries that the test suite will
#    depend on. You do NOT have to list those libraries already listed by the 
#    module.cmake file as these will be used.
#
#
# example usage:
#  boost_additional_test_dependencies(signals BOOST_DEPENDS test optional)
#
#
#  TDS 20091103:  
#  For the moment we don't need this, since tests are now traversed
#  after project directories (so all boost lib dependency targets are
#  visible to all tests) and modularization has crashed and burned.
#
macro(boost_additional_test_dependencies libname)
  # NOTE DISABLED
  if (FALSE)
  parse_arguments(BOOST_TEST 
    "BOOST_DEPENDS"
    ""
    ${ARGN}
  )
  # Get the list of libraries that this test depends on
  # Set THIS_PROJECT_DEPENDS_ALL to the set of all of its
  # dependencies, its dependencies' dependencies, etc., transitively.
  string(TOUPPER "BOOST_${libname}_DEPENDS" THIS_PROJECT_DEPENDS)
  set(THIS_TEST_DEPENDS_ALL ${libname} ${${THIS_PROJECT_DEPENDS}} )
  set(ADDED_DEPS TRUE)
  while (ADDED_DEPS)
    set(ADDED_DEPS FALSE)
    foreach(DEP ${THIS_TEST_DEPENDS_ALL})
      string(TOUPPER "BOOST_${DEP}_DEPENDS" DEP_DEPENDS)
      foreach(DEPDEP ${${DEP_DEPENDS}})
        list(FIND THIS_TEST_DEPENDS_ALL ${DEPDEP} DEPDEP_INDEX)
        if (DEPDEP_INDEX EQUAL -1)
          list(APPEND THIS_TEST_DEPENDS_ALL ${DEPDEP})
          set(ADDED_DEPS TRUE)
        endif()
      endforeach()
    endforeach()
  endwhile()
 
  # Get the list of dependencies for the additional libraries arguments
  foreach(additional_lib ${BOOST_TEST_BOOST_DEPENDS})
   list(FIND THIS_TEST_DEPENDS_ALL ${additional_lib} DEPDEP_INDEX)
   if (DEPDEP_INDEX EQUAL -1)
     list(APPEND THIS_TEST_DEPENDS_ALL ${additional_lib})
     set(ADDED_DEPS TRUE)
   endif()
    string(TOUPPER "BOOST_${additional_lib}_DEPENDS" THIS_PROJECT_DEPENDS)
    set(ADDED_DEPS TRUE)
    while (ADDED_DEPS)
      set(ADDED_DEPS FALSE)
      foreach(DEP ${THIS_TEST_DEPENDS_ALL})
        string(TOUPPER "BOOST_${DEP}_DEPENDS" DEP_DEPENDS)
        foreach(DEPDEP ${${DEP_DEPENDS}})
          list(FIND THIS_TEST_DEPENDS_ALL ${DEPDEP} DEPDEP_INDEX)
          if (DEPDEP_INDEX EQUAL -1)
            list(APPEND THIS_TEST_DEPENDS_ALL ${DEPDEP})
            set(ADDED_DEPS TRUE)
          endif()
        endforeach()
      endforeach()
    endwhile()
  endforeach()
  
  foreach (include ${THIS_TEST_DEPENDS_ALL})
    #
    # Modularization temporarily disabled
    #
    # include_directories("${Boost_SOURCE_DIR}/libs/${include}/include")
    #
  endforeach (include ${includes})
endif()
  
endmacro(boost_additional_test_dependencies libname)
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# This macro is an internal utility macro that helps parse the
# arguments passed to the Boost testing commands. It will generally
# not be used by Boost developers.
#
#   boost_test_parse_args(testname 
#                         [source1 source2 ...]
#                         [ARGS arg1 arg2... ]
#                         [COMPILE_FLAGS compileflags]
#                         [LINK_FLAGS linkflags]
#                         [LINK_LIBS linklibs]
#                         [DEPENDS libdepend1 libdepend2 ...]
#                         [KNOWN_FAILURES string1 string2 ...]
#                         [COMPILE] [RUN] [FAIL])
#
# testname is the name of the test. The remaining arguments passed to
# this macro will be parsed and categorized for the developer-level
# test macros to use. 
#
# Variables affected:
#
#   BOOST_TEST_OKAY: Will be set to TRUE if it is okay to build and
#   run this test.
#
#   BOOST_TEST_SOURCES: Will be populated with the set of source files
#   that should be used to compile this test. If the user has provided
#   source files, BOOST_TEST_SOURCES will contain those; otherwise,
#   BOOST_TEST_SOURCES will only contain "testname.cpp".
#
#   BOOST_TEST_TESTNAME: A (hopefully) globally unique target name
#   for the test, constructed from PROJECT-testname-TAG
#
#   BOOST_TEST_arg: Will be populated with the arguments provided for
#   the arguemnt "arg", where "arg" can be any of the extra arguments
#   specified above.
#
#   
macro(boost_test_parse_args testname)
  #message("boost_test_parse_args ${testname} ${ARGN}")
  set(BOOST_TEST_OKAY TRUE)
  set(BOOST_TEST_COMPILE_FLAGS "")
  parse_arguments(BOOST_TEST 
    "BOOST_LIB;LINK_LIBS;LINK_FLAGS;DEPENDS;COMPILE_FLAGS;ARGS;EXTRA_OPTIONS;KNOWN_FAILURES"
    "COMPILE;RUN;LINK;FAIL;RELEASE;DEBUG"
    ${ARGN}
    )
    
  # Check each of the dependencies to see if we can still build this
  # test.
  foreach(ARG ${BOOST_TEST_DEPENDS})
    get_target_property(DEPEND_TYPE ${ARG} TYPE)
    get_target_property(DEPEND_LOCATION ${ARG} LOCATION)
    # If building static libraries is turned off, don't try to build
    # the test
    #if (NOT ENABLE_STATIC AND ${DEPEND_TYPE} STREQUAL "STATIC_LIBRARY")
    #set(BOOST_TEST_OKAY FALSE)
    #endif (NOT ENABLE_STATIC AND ${DEPEND_TYPE} STREQUAL "STATIC_LIBRARY")

    # If building shared libraries is turned off, don't try to build
    # the test
    #if (NOT ENABLE_SHARED AND ${DEPEND_TYPE} STREQUAL "SHARED_LIBRARY")
    #set(BOOST_TEST_OKAY FALSE)
    #endif (NOT ENABLE_SHARED AND ${DEPEND_TYPE} STREQUAL "SHARED_LIBRARY")
  endforeach(ARG ${BOOST_TEST_DEPENDS})

  # Setup the SOURCES variables. If no sources are specified, use the
  # name of the test.cpp
  if (BOOST_TEST_DEFAULT_ARGS)
    set(BOOST_TEST_SOURCES ${BOOST_TEST_DEFAULT_ARGS})
  else (BOOST_TEST_DEFAULT_ARGS)
    set(BOOST_TEST_SOURCES "${testname}.cpp")
  endif (BOOST_TEST_DEFAULT_ARGS)

  set(BOOST_TEST_TESTNAME "${BOOST_PROJECT_NAME}-${testname}")
  #message("testname: ${BOOST_TEST_TESTNAME}")
  # If testing is turned off, this test is not okay
endmacro(boost_test_parse_args)

# This macro attaches a the "known-failure" label to the given test
# target if the build name matches any of the declared, known
# failures.
macro(boost_test_known_failures TEST)
  foreach(PATTERN ${ARGN})
    if (${BUILDNAME} MATCHES ${PATTERN})
      set_tests_properties("${BOOST_PROJECT_NAME}-${TEST}"
        PROPERTIES 
	LABELS "${BOOST_PROJECT_NAME};known-failure"
	WILL_FAIL TRUE
	)
    endif()
  endforeach()
endmacro(boost_test_known_failures)


# This macro creates a Boost regression test that will be executed. If
# the test can be built, executed, and exits with a return code of
# zero, it will be considered to have passed.
#
#   boost_test_run(testname 
#                  [source1 source2 ...]
#                  [ARGS arg1 arg2... ]
#                  [COMPILE_FLAGS compileflags]
#                  [LINK_FLAGS linkflags]
#                  [LINK_LIBS linklibs]
#                  [DEPENDS libdepend1 libdepend2 ...]
#                  [EXTRA_OPTIONS option1 option2 ...])
#
# testname is the name of the test. source1, source2, etc. are the
# source files that will be built and linked into the test
# executable. If no source files are provided, the file "testname.cpp"
# will be used instead.
#
# There are several optional arguments to control how the regression
# test is built and executed:
#
#   ARGS: Provides additional arguments that will be passed to the
#   test executable when it is run.
#
#   COMPILE_FLAGS: Provides additional compilation flags that will be
#   used when building this test. For example, one might want to add
#   "-DBOOST_SIGNALS_ASSERT=1" to turn on assertions within the library.
#
#   LINK_FLAGS: Provides additional flags that will be passed to the
#   linker when linking the test excecutable. This option should not
#   be used to link in additional libraries; see LINK_LIBS and
#   DEPENDS.
#
#   LINK_LIBS: Provides additional libraries against which the test
#   executable will be linked. For example, one might provide "expat"
#   as options to LINK_LIBS, to state that this executable should be
#   linked against the external "expat" library. Use LINK_LIBS for
#   libraries external to Boost; for Boost libraries, use DEPENDS.
#
#   DEPENDS: States that this test executable depends on and links
#   against another Boost library. The argument to DEPENDS should be
#   the name of a particular variant of a Boost library, e.g.,
#   boost_signals-static.
#
#   EXTRA_OPTIONS: Provide extra options that will be passed on to 
#   boost_add_executable.
#
# Example:
#   boost_test_run(signal_test DEPENDS boost_signals)
macro(boost_test_run testname)
  boost_test_parse_args(${testname} ${ARGN} RUN)
  #
  # On windows, tests have to go in the same directory as
  # DLLs.  
  # 
  if (NOT CMAKE_HOST_WIN32)
    set(THIS_TEST_OUTPUT_NAME tests/${BOOST_PROJECT_NAME}/${testname})
  else()
    set(THIS_TEST_OUTPUT_NAME ${BOOST_PROJECT_NAME}-${testname})
  endif()

  if (BOOST_TEST_OKAY)  
    boost_add_executable(${testname} ${BOOST_TEST_SOURCES}
      DEPENDS "${BOOST_TEST_DEPENDS}"
      OUTPUT_NAME ${THIS_TEST_OUTPUT_NAME}
      LINK_LIBS ${BOOST_TEST_LINK_LIBS}
      LINK_FLAGS ${BOOST_TEST_LINK_FLAGS}
      COMPILE_FLAGS ${BOOST_TEST_COMPILE_FLAGS}
      NO_INSTALL 
      ${BOOST_TEST_EXTRA_OPTIONS})

    if (THIS_EXE_OKAY)
      #
      # Fixup path for visual studio per instructions from Brad King:  
      #
      get_target_property(THIS_TEST_LOCATION ${BOOST_TEST_TESTNAME}
        LOCATION)
      string(REGEX REPLACE "\\$\\(.*\\)" "\${CTEST_CONFIGURATION_TYPE}"
        THIS_TEST_LOCATION "${THIS_TEST_LOCATION}")

      add_test (${BOOST_TEST_TESTNAME} 
	${VALGRIND_EXECUTABLE}
	${VALGRIND_FLAGS}
        ${THIS_TEST_LOCATION}
        ${BOOST_TEST_ARGS})

      set_tests_properties(${BOOST_TEST_TESTNAME}
        PROPERTIES
        LABELS "${BOOST_PROJECT_NAME}"
        )
      boost_test_known_failures(${testname} ${BOOST_TEST_KNOWN_FAILURES})

      if (BOOST_TEST_FAIL)
        set_tests_properties(${BOOST_TEST_TESTNAME} PROPERTIES WILL_FAIL ON)
      endif ()
    endif(THIS_EXE_OKAY)
  endif (BOOST_TEST_OKAY)
endmacro(boost_test_run)

# 
# This macro creates a boost regression test that will be run but is
# expected to fail (exit with nonzero return code).
# See boost_test_run()
# 
macro(boost_test_run_fail testname)
  boost_test_run(${testname} ${ARGN} FAIL)
endmacro(boost_test_run_fail)

# This macro creates a Boost regression test that will be compiled,
# but not linked or executed. If the test can be compiled with no
# failures, the test passes.
#
#   boost_test_compile(testname 
#                      [source1]
#                      [COMPILE_FLAGS compileflags])
#
# testname is the name of the test. source1 is the name of the source
# file that will be built. If no source file is provided, the file
# "testname.cpp" will be used instead.
#
# The COMPILE_FLAGS argument provides additional arguments that will
# be passed to the compiler when building this test.

# Example:
#   boost_test_compile(advance)
macro(boost_test_compile testname)
  boost_test_parse_args(${testname} ${ARGN} COMPILE)

  if (BOOST_TEST_FAIL)
    set (test_pass "FAILED")
  else()
    set (test_pass "PASSED")
  endif()

  if (BOOST_TEST_OKAY)
  
    # Determine the include directories to pass along to the underlying
    # project.
    # works but not great
    get_directory_property(BOOST_TEST_INCLUDE_DIRS INCLUDE_DIRECTORIES)
    set(BOOST_TEST_INCLUDES "")
    foreach(DIR ${BOOST_TEST_INCLUDE_DIRS})
      set(BOOST_TEST_INCLUDES "${BOOST_TEST_INCLUDES};${DIR}")
    endforeach(DIR ${BOOST_TEST_INCLUDE_DIRS})

    add_test(${BOOST_TEST_TESTNAME}
      ${CMAKE_CTEST_COMMAND}
      --build-and-test
      ${Boost_SOURCE_DIR}/tools/build/CMake/CompileTest
      ${Boost_BINARY_DIR}/tools/build/CMake/CompileTest
      --build-generator ${CMAKE_GENERATOR}
      --build-makeprogram ${CMAKE_MAKE_PROGRAM}
      --build-project CompileTest
      --build-options 
      "-DSOURCE:STRING=${CMAKE_CURRENT_SOURCE_DIR}/${BOOST_TEST_SOURCES}"
      "-DINCLUDES:STRING=${BOOST_TEST_INCLUDES}"
      "-DCOMPILE_FLAGS:STRING=${BOOST_TEST_COMPILE_FLAGS}"
      )

    set_tests_properties(${BOOST_TEST_TESTNAME}
      PROPERTIES
      LABELS "${BOOST_PROJECT_NAME}"
      )

    boost_test_known_failures(${testname} ${BOOST_TEST_KNOWN_FAILURES})

    if (BOOST_TEST_FAIL)
      set_tests_properties(${BOOST_TEST_TESTNAME} PROPERTIES WILL_FAIL ON)      
    endif ()
  endif(BOOST_TEST_OKAY)
endmacro(boost_test_compile)

#
# This macro creates a Boost regression test that is expected to 
# *fail* to compile.   See boost_test_compile()
#
macro(boost_test_compile_fail testname)
  boost_test_compile(${testname} ${ARGN} FAIL)
endmacro(boost_test_compile_fail)




#
# boost_test_link:
#
#
# Each library "exports" itself to
# ${CMAKE_BINARY_DIR}/exports/<variantname>.cmake
#
# The list of 'depends' for these libraries has to match one of those
# files, this way the export mechanism works.  The generated
# cmakelists will include() those exported .cmake files, for each
# DEPENDS.
#
#
macro(boost_test_link testname)
  boost_test_parse_args(${testname} ${ARGN} LINK)
  if(BOOST_TEST_OKAY)
    # Determine the include directories to pass along to the underlying
    # project.
    # works but not great
    get_directory_property(BOOST_TEST_INCLUDE_DIRS INCLUDE_DIRECTORIES)
    set(BOOST_TEST_INCLUDES "")
    foreach(DIR ${BOOST_TEST_INCLUDE_DIRS})
      set(BOOST_TEST_INCLUDES "${BOOST_TEST_INCLUDES};${DIR}")
    endforeach(DIR ${BOOST_TEST_INCLUDE_DIRS})

    add_test(${BOOST_TEST_TESTNAME}
      ${CMAKE_CTEST_COMMAND}
      -VV
      --build-and-test
      ${Boost_SOURCE_DIR}/tools/build/CMake/LinkTest
      ${Boost_BINARY_DIR}/tools/build/CMake/LinkTest
      --build-generator ${CMAKE_GENERATOR}
      --build-makeprogram ${CMAKE_MAKE_PROGRAM}
      --build-project LinkTest
      --build-options 
      "-DCMAKE_CXX_COMPILER:FILEPATH=${CMAKE_CXX_COMPILER}"
      "-DCMAKE_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER}"
      "-DBOOST_EXPORTS_DIR:FILEPATH=${CMAKE_BINARY_DIR}/exports"
      "-DSOURCE:STRING=${CMAKE_CURRENT_SOURCE_DIR}/${BOOST_TEST_SOURCES}"
      "-DINCLUDES:STRING=${BOOST_TEST_INCLUDES}"
      "-DCOMPILE_FLAGS:STRING=${BOOST_TEST_COMPILE_FLAGS}"
      "-DLINK_LIBS:STRING=${BOOST_TEST_LINK_LIBS}"
      "-DDEPENDS:STRING=${BOOST_TEST_DEPENDS}"
      )

    set_tests_properties(${BOOST_TEST_TESTNAME}
      PROPERTIES
      LABELS "${BOOST_PROJECT_NAME}"
      )

    boost_test_known_failures(${testname} ${BOOST_TEST_KNOWN_FAILURES})

    if (BOOST_TEST_FAIL)
      set_tests_properties(${BOOST_TEST_TESTNAME} PROPERTIES WILL_FAIL ON)      
    endif ()
  endif(BOOST_TEST_OKAY)
endmacro(boost_test_link)

