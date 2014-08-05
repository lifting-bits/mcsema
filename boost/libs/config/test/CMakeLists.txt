# Copyright John Maddock and Douglas Gregor.
# Use, modification and distribution are subject to the 
# Boost Software License, Version 1.0. (See accompanying file 
# LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
if(MSVC)
  set(BOOST_CONFIG_MSVC_STATIC_OPTIONS STATIC STATIC_RUNTIME)
endif(MSVC)
if(BORLAND)
  set(BOOST_CONFIG_BORLAND_STATIC_OPTIONS STATIC STATIC_RUNTIME)
endif(BORLAND)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  set(BOOST_CONFIG_STATIC_THREAD_LIBS LINK_LIBS pthread rt)
endif(CMAKE_SYSTEM_NAME MATCHES "Linux")

boost_additional_test_dependencies(config BOOST_DEPENDS test)

boost_test_run(config_test_threaded config_test.cpp 
  EXTRA_OPTIONS MULTI_THREADED)
  
boost_test_run(config_test 
  EXTRA_OPTIONS SINGLE_THREADED ${BOOST_CONFIG_MSVC_STATIC_OPTIONS}
                ${BOOST_CONFIG_STATIC_THREAD_LIBS})
boost_test_run(config_info_threaded config_info.cpp 
  EXTRA_OPTIONS MULTI_THREADED)
boost_test_run(config_info
  EXTRA_OPTIONS SINGLE_THREADED ${BOOST_CONFIG_MSVC_STATIC_OPTIONS})
boost_test_run(math_info
  EXTRA_OPTIONS ${BOOST_CONFIG_BORLAND_STATIC_OPTIONS})
  

boost_test_run(limits_test DEPENDS boost_test_exec_monitor)
boost_test_run(abi_test abi/abi_test.cpp abi/main.cpp)

# TODO: config_link_test
boost_test_compile_fail(test_thread_fail1 threads/test_thread_fail1.cpp)
boost_test_compile_fail(test_thread_fail2 threads/test_thread_fail2.cpp)