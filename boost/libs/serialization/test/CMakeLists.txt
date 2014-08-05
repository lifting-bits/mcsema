#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
# The set of archives that we will use for testing the Serialization
# library
set(BOOST_ARCHIVE_LIST 
  "text_archive" 
  "text_warchive" 
  "binary_archive" 
  "xml_archive" 
  "xml_warchive"
  )

# The serialization_test macro declares a set of tests of the
# serialization library. For each invocation of serialization_test,
# this macro will build separate static and dynamic tests.
macro(serialization_test testname)
  parse_arguments(BSL_TEST "" "NO_LIBS;POLYMORPHIC" ${ARGN})

  if(NOT BSL_TEST_DEFAULT_ARGS)
    set(BSL_TEST_SOURCES "${testname}.cpp")
  else(NOT BSL_TEST_DEFAULT_ARGS)
    set(BSL_TEST_SOURCES "${BSL_TEST_DEFAULT_ARGS}")
  endif(NOT BSL_TEST_DEFAULT_ARGS)

  if (BSL_TEST_POLYMORPHIC)
    set(BSL_TEST_POLY "polymorphic_")
  elseif(BSL_TEST_POLYMORPHIC)
    set(BSL_TEST_POLY "")
  endif(BSL_TEST_POLYMORPHIC)
  
  set(BSL_TEST_LIBRARIES) 
  if(NOT BSL_NO_LIBS)
    set(BSL_TEST_LIBRARIES "boost_serialization")
  endif(NOT BSL_NO_LIBS)

  # Tests linking against the static serialization library
  boost_test_run("${testname}"
    ${BSL_TEST_SOURCES}
    STATIC
    DEPENDS ${BSL_TEST_LIBRARIES}
    COMPILE_FLAGS "-DBOOST_LIB_DIAGNOSTIC=1")
    
  # Tests linking against the shared serialization library
  boost_test_run("${testname}_dll"
    ${BSL_TEST_SOURCES}
    SHARED
    DEPENDS ${BSL_TEST_LIBRARIES}
    COMPILE_FLAGS "-DBOOST_LIB_DIAGNOSTIC=1 -DBOOST_ALL_DYN_LINK=1")
endmacro(serialization_test)

# Like serialization_test, but runs the same test for all archive types.
macro(serialization_test_allarchives testname)
  parse_arguments(BSL_TEST "" "NO_LIBS;POLYMORPHIC" ${ARGN})

  if(NOT BSL_TEST_DEFAULT_ARGS)
    set(BSL_TEST_SOURCES "${testname}.cpp")
  else(NOT BSL_TEST_DEFAULT_ARGS)
    set(BSL_TEST_SOURCES "${BSL_TEST_DEFAULT_ARGS}")
  endif(NOT BSL_TEST_DEFAULT_ARGS)

  if (BSL_TEST_POLYMORPHIC)
    set(BSL_TEST_POLY "polymorphic_")
  elseif(BSL_TEST_POLYMORPHIC)
    set(BSL_TEST_POLY "")
  endif(BSL_TEST_POLYMORPHIC)
  
  foreach(ARCHIVE ${BOOST_ARCHIVE_LIST})
    set(BSL_TEST_LIBRARIES) 
    if(NOT BSL_NO_LIBS)
      set(BSL_TEST_LIBRARIES "boost_serialization")
      if(ARCHIVE MATCHES ".*warchive")
        set(BSL_TEST_LIBRARIES "boost_wserialization" ${BSL_TEST_LIBRARIES})
      endif(ARCHIVE MATCHES ".*warchive")
    endif(NOT BSL_NO_LIBS)

    # Tests linking against the static serialization library
    boost_test_run("${testname}_${ARCHIVE}"
      ${BSL_TEST_SOURCES}
      STATIC
      DEPENDS ${BSL_TEST_LIBRARIES}
      COMPILE_FLAGS "-DBOOST_ARCHIVE_TEST=${BSL_TEST_POLY}${ARCHIVE}.hpp -DBOOST_LIB_DIAGNOSTIC=1")
    
    # Tests linking against the shared serialization library
    boost_test_run("${testname}_${ARCHIVE}_dll"
      ${BSL_TEST_SOURCES}
      SHARED
      DEPENDS ${BSL_TEST_LIBRARIES}
      COMPILE_FLAGS "-DBOOST_ARCHIVE_TEST=${BSL_TEST_POLY}${ARCHIVE}.hpp -DBOOST_LIB_DIAGNOSTIC=1 -DBOOST_ALL_DYN_LINK=1")
  endforeach(ARCHIVE ${BOOST_ARCHIVE_LIST})
endmacro(serialization_test_allarchives)

boost_additional_test_dependencies(serialization BOOST_DEPENDS test)


serialization_test_allarchives(test_array test_array.cpp A.cpp)
serialization_test_allarchives(test_binary)
serialization_test_allarchives(test_complex)
serialization_test_allarchives(test_contained_class test_contained_class.cpp A.cpp)
serialization_test_allarchives(test_cyclic_ptrs test_cyclic_ptrs.cpp A.cpp)
serialization_test_allarchives(test_delete_pointer)
serialization_test_allarchives(test_deque test_deque.cpp A.cpp)
# serialization_test_allarchives(test_derived)
serialization_test_allarchives(test_derived_class test_derived_class.cpp A.cpp)
serialization_test_allarchives(test_derived_class_ptr test_derived_class_ptr.cpp A.cpp)
serialization_test_allarchives(test_diamond)
serialization_test_allarchives(test_exported test_exported.cpp polymorphic_base.cpp)
serialization_test_allarchives(test_class_info_save)
serialization_test_allarchives(test_class_info_load)
serialization_test_allarchives(test_object)
serialization_test_allarchives(test_primitive)
serialization_test_allarchives(test_list test_list.cpp A.cpp)
serialization_test_allarchives(test_list_ptrs test_list_ptrs.cpp A.cpp)
serialization_test_allarchives(test_map test_map.cpp A.cpp)
serialization_test_allarchives(test_mi)
serialization_test_allarchives(test_multiple_ptrs test_multiple_ptrs.cpp A.cpp)
serialization_test_allarchives(test_no_rtti test_no_rtti.cpp
  polymorphic_base.cpp polymorphic_derived1.cpp polymorphic_derived2.cpp)
serialization_test_allarchives(test_non_intrusive)
serialization_test_allarchives(test_non_default_ctor)
serialization_test_allarchives(test_non_default_ctor2)
serialization_test_allarchives(test_null_ptr)
serialization_test_allarchives(test_nvp test_nvp.cpp A.cpp)
serialization_test_allarchives(test_recursion test_recursion.cpp A.cpp)
serialization_test_allarchives(test_registered)
serialization_test_allarchives(test_set test_set.cpp A.cpp)
serialization_test_allarchives(test_simple_class test_simple_class.cpp A.cpp)
serialization_test_allarchives(test_simple_class_ptr test_simple_class_ptr.cpp A.cpp)
serialization_test_allarchives(test_split)
serialization_test_allarchives(test_tracking)
serialization_test_allarchives(test_unregistered)
serialization_test_allarchives(test_valarray)
serialization_test_allarchives(test_variant test_variant.cpp A.cpp)
serialization_test_allarchives(test_vector test_vector.cpp A.cpp)
serialization_test_allarchives(test_optional)
serialization_test_allarchives(test_shared_ptr)
serialization_test_allarchives(test_shared_ptr_132)
serialization_test_allarchives(test_polymorphic POLYMORPHIC 
  test_polymorphic.cpp test_polymorphic_A.cpp A.cpp)

serialization_test(test_private_ctor)
serialization_test(test_reset_object_address test_reset_object_address.cpp A.cpp)
serialization_test(test_void_cast)
serialization_test(test_mult_archive_types)

serialization_test(test_iterators NO_LIBS)
serialization_test(test_iterators_base64 NO_LIBS)
serialization_test(test_inclusion NO_LIBS)
serialization_test(test_smart_cast NO_LIBS)

serialization_test(test_utf8_codecvt 
  test_utf8_codecvt.cpp ../src/utf8_codecvt_facet.cpp NO_LIBS)

serialization_test(test_serialization_iterators test_iterators.cpp NO_LIBS)
serialization_test(test_static_warning NO_LIBS)
serialization_test(test_codecvt_null 
  test_codecvt_null.cpp ../src/codecvt_null.cpp NO_LIBS)

# should fail compilation
boost_test_compile_fail(test_not_serializable)
boost_test_compile_fail(test_traits_fail)
boost_test_compile_fail(test_const_load_fail1)
boost_test_compile_fail(test_const_load_fail2)
boost_test_compile_fail(test_const_load_fail3)
boost_test_compile_fail(test_const_load_fail1_nvp)
boost_test_compile_fail(test_const_load_fail2_nvp)
boost_test_compile_fail(test_const_load_fail3_nvp)

boost_test_compile(test_static_warning)
boost_test_compile(test_const_save_warn1)
boost_test_compile(test_const_save_warn2)
boost_test_compile(test_const_save_warn3)

# note - library unable to detect there errors for now
#boost_test_compile_fail(test_const_save_fail1_nvp)
#boost_test_compile_fail(test_const_save_fail2_nvp)
#boost_test_compile_fail(test_const_save_fail3_nvp)

# should compile
boost_test_compile(test_traits_pass)
boost_test_compile(test_const_pass)
