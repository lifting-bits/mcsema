#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(property_tree BOOST_DEPENDS test serialization)


ADD_DEFINITIONS(-DBOOST_ALL_NO_LIB) # -DBOOST_PROPERTY_TREE_STATIC_LINK

SET(TEST_SUFFIXES 
  info_parser json_parser ini_parser xml_parser_rapidxml
  multi_module1 multi_module2
  # registry_parser
  )

FOREACH(test_suffix ${TEST_SUFFIXES})
  boost_test_run(test_${test_suffix} test_${test_suffix}.cpp)
ENDFOREACH(test_suffix ${TEST_SUFFIXES})

boost_test_run(test_property_tree test_property_tree.cpp
  DEPENDS boost_serialization SHARED)
