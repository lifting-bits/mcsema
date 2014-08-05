#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(ratio BOOST_DEPENDS test)

#
set(TESTS 
ratio_arithmetic
ratio_comparison
ratio_extensions
ratio_io
ratio_ratio)

foreach(TEST ${TESTS})
  boost_test_run(${TEST} DEPENDS boost_unit_test_framework)
endforeach(TEST ${TESTS})

if(WIN32)
  message("Need to turn on iterator debugging")
endif(WIN32)

#
ratio_test_run(ratio_test) 
ratio_test_run(typedefs_pass) 
