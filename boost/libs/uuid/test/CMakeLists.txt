#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(uuid BOOST_DEPENDS test serialization)


ADD_DEFINITIONS(-DBOOST_ALL_NO_LIB) # -DBOOST_UUID_STATIC_LINK)


# Make sure each header file is self-contained
SET(UUID_SUFFIXES uuid uuid_io uuid_serialize	uuid_generators nil_generator
  name_generator string_generator random_generator)

FOREACH(uuid_suffix ${UUID_SUFFIXES})
  boost_test_compile(compile_${uuid_suffix} compile_${uuid_suffix}.cpp)
ENDFOREACH(uuid_suffix ${UUID_SUFFIXES})

boost_test_compile(compile_uuid_no_type_traits
  compile_uuid.cpp
  COMPILE_FLAGS -DBOOST_UUID_NO_TYPE_TRAITS
  )

#
SET(TEST_SUFFIXES
  uuid # main test
  io # uuid_io.hpp
  nil_generator name_generator string_generator random_generator # generators
  tagging # tagging an object
  uuid_class # test uuid class
  sha1 # test sha1 hash function
  )

FOREACH(test_suffix ${TEST_SUFFIXES})
  boost_test_run(test_${test_suffix} test_${test_suffix}.cpp)
ENDFOREACH(test_suffix ${TEST_SUFFIXES})

# Test inclucing all .hpp files in 2 translations units
# to look for issues when using multiple translation units
# eg. missing inline on a global functionstate is not missing
boost_test_run(test_include test_include1.cpp test_include2.cpp)

# Test serializing uuids
boost_test_run(test_serialization test_serialization.cpp
  DEPENDS boost_serialization SHARED)

# TODO - This test fails to like with boost_wserialization
#boost_test_run(test_serialization test_serialization.cpp
#  DEPENDS boost_serialization boost_wserialization SHARED
#  COMPILE_FLAGS -DBOOST_NO_STD_WSTREAMBUF)
