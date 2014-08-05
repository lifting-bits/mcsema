#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(iostreams BOOST_DEPENDS test)


# Helper macro to create tests for the iostreams library
macro(iostreams_test TESTNAME)
  boost_test_run(${TESTNAME} 
    ${ARGN}
    DEPENDS boost_unit_test_framework
    COMPILE_FLAGS "-DBOOST_IOSTREAMS_NO_LIB")
endmacro(iostreams_test)

iostreams_test(array_test)
iostreams_test(auto_close_test)
iostreams_test(buffer_size_test)
iostreams_test(code_converter_test 
  code_converter_test.cpp detail/utf8_codecvt_facet.cpp)
iostreams_test(compose_test)
iostreams_test(component_access_test)
iostreams_test(copy_test)
iostreams_test(counter_test)
iostreams_test(direct_adapter_test)
iostreams_test(example_test)
iostreams_test(file_test)
boost_test_run(file_descriptor_test
  DEPENDS boost_unit_test_framework boost_iostreams
  COMPILE_FLAGS "-DBOOST_IOSTREAMS_NO_LIB")
iostreams_test(filtering_stream_test)
iostreams_test(finite_state_filter_test)
iostreams_test(flush_test)
iostreams_test(invert_test)
iostreams_test(line_filter_test)
boost_test_run(mapped_file_test
  DEPENDS boost_unit_test_framework boost_iostreams
  COMPILE_FLAGS "-DBOOST_IOSTREAMS_NO_LIB")
iostreams_test(newline_test)
iostreams_test(null_test)
iostreams_test(pipeline_test)
boost_test_run(regex_filter_test
  DEPENDS boost_unit_test_framework boost_regex
  COMPILE_FLAGS "-DBOOST_IOSTREAMS_NO_LIB")
iostreams_test(restrict_test)
iostreams_test(seekable_file_test)
iostreams_test(seekable_filter_test)
iostreams_test(stdio_filter_test)
iostreams_test(symmetric_filter_test)
iostreams_test(tee_test)
iostreams_test(wide_stream_test)

if (ZLIB_FOUND)
  boost_test_run(gzip_test
    DEPENDS boost_unit_test_framework boost_iostreams
    COMPILE_FLAGS "-DBOOST_IOSTREAMS_NO_LIB")
  boost_test_run(zlib_test
    DEPENDS boost_unit_test_framework boost_iostreams
    COMPILE_FLAGS "-DBOOST_IOSTREAMS_NO_LIB")
endif(ZLIB_FOUND)

# Find BZip2. If it's available, test it
if (BZIP2_FOUND)
  boost_test_run(bzip2_test
    DEPENDS boost_unit_test_framework boost_iostreams
    COMPILE_FLAGS "-DBOOST_IOSTREAMS_NO_LIB")
endif(BZIP2_FOUND)
