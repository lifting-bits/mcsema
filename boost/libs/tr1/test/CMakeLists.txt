#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(tr1 BOOST_DEPENDS test)


include_directories(${Boost_SOURCE_DIR}/boost/tr1/tr1)
include_directories(${Boost_SOURCE_DIR}/libs/tr1/include/boost/tr1/tr1)

if (BORLAND)
  # Borland's broken include mechanism needs these extra headers:
  include_directories(${Boost_SOURCE_DIR}/boost/tr1/tr1/bcc32)  
  include_directories(${Boost_SOURCE_DIR}/libs/tr1/include/boost/tr1/tr1/bcc32)
endif (BORLAND)

macro(boost_glob_test_compile path glob_par compile_flags)
  list_contains(WITH_STD "WITH_STD" ${ARGN})
  list_contains(STD_HEADER_TEST "STD_HEADER_TEST" ${ARGN})
  file(GLOB file_list ${path}/${glob_par})
  foreach (current_file ${file_list})
    get_filename_component(file_name ${current_file} NAME_WE)
    set(test_name "${file_name}")
    if (${STD_HEADER_TEST})
      set(test_name "${file_name}_header")
    endif ()
    boost_test_compile(${test_name} ${path}/${file_name}.cpp 
      COMPILE_FLAGS "${compile_flags}")
    if (WITH_STD)
      boost_test_compile(${file_name}_std ${path}/${file_name}.cpp 
        COMPILE_FLAGS ${compile_flags} -DTEST_STD_HEADERS=1)
    endif (WITH_STD)
  endforeach (current_file)
endmacro(boost_glob_test_compile)

macro(boost_glob_test_compile_fail patch glob_par compile_flags)
  file(GLOB file_list ${glob_par})
  foreach (current_file ${file_list})
    get_filename_component(file_name ${current_file} NAME_WE)
    boost_test_compile_fail(${file_name} ${path}/${file_name}.cpp COMPILE_FLAGS "${compile_flags}")
	  endforeach (current_file)
endmacro(boost_glob_test_compile_fail)

macro(boost_glob_test_run path glob_par compile_flags)
  list_contains(WITH_STD "WITH_STD" ${ARGN})
  file(GLOB file_list ${path}/${glob_par})
  foreach (current_file ${file_list})
    get_filename_component(file_name ${current_file} NAME_WE)
    boost_test_run(${file_name} ${path}/${file_name}.cpp COMPILE_FLAGS "${compile_flags}")
    if (WITH_STD)
      boost_test_run(${file_name}_std ${path}/${file_name}.cpp 
        COMPILE_FLAGS ${compile_flags} -DTEST_STD_HEADERS=1)
    endif (WITH_STD)
  endforeach (current_file)
endmacro(boost_glob_test_run)


boost_glob_test_compile(. test*.cpp "" WITH_STD)
boost_glob_test_run(. run*.cpp "" WITH_STD)
boost_glob_test_compile_fail(config tr1_has_tr1*fail.cpp "")
boost_glob_test_compile(config tr1_has_tr1*pass.cpp "")
boost_glob_test_run(type_traits *.cpp "")

# TODO: there's a problem here where the testing code is generating duplicate 
# target names.
message(STATUS "TR1 tests need some love")
# boost_glob_test_compile(std_headers *.cpp "-DTEST_STD=1" STD_HEADER_TEST)
boost_glob_test_compile(cyclic_depend *.cpp "")

# Known failures
boost_test_known_failures(test_cmath_tricky_std "gcc-4.0.[0-9]-.*")
boost_test_known_failures(test_mem_fn_tricky_std "gcc-4.0.[0-9]-.*")
boost_test_known_failures(test_ref_wrapper_tricky_std "gcc-4.0.[0-9]-.*")