#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(random BOOST_DEPENDS test)

foreach(urngs
    rand48
    minstd_rand0
    minstd_rand
    ecuyer1988
    kreutzer1986
    hellekalek1995
    mt11213b
    mt19937
    lagged_fibonacci
    lagged_fibonacci607
    ranlux3
    ranlux4
    ranlux3_01
    ranlux4_01
    ranlux64_3_01
    ranlux64_4_01
    taus88)
  boost_test_run(test_${urngs} 
    instantiate.cpp
    COMPILE_FLAGS -DBOOST_RANDOM_URNG_TEST=${urngs}
    )
endforeach()

ADD_DEFINITIONS(-DBOOST_ALL_NO_LIB) # -DBOOST_RANDOM_STATIC_LINK

SET(TESTS test_random_device)

FOREACH(test ${TESTS})
  boost_test_run(${test}_static
    ${test}.cpp
    DEPENDS boost_random STATIC
    COMPILE_FLAGS -DBOOST_RANDOM_STATIC_LINK)
  boost_test_run(${test}_dynamic
    ${test}.cpp
    DEPENDS boost_random SHARED
    COMPILE_FLAGS -DBOOST_RANDOM_DYN_LINK)
ENDFOREACH(test ${TESTS})

boost_test_run(random_demo ../example/random_demo.cpp)
boost_test_run(random_test random_test.cpp)
boost_test_run(validate validate.cpp)
#boost_test_run(test_random_device test_random_device.cpp)
#boost_test_run(statistic_tests statistic_tests.cpp)
