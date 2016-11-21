project(mc-sema)
cmake_minimum_required(VERSION 2.8)

include(ExternalProject)
ExternalProject_add(boost
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/boost
  CMAKE_CACHE_ARGS
  -DBUILD_PROJECTS:STRING=thread;system;filesystem;date_time;program_options
  -DCMAKE_INSTALL_PREFIX:STRING=${CMAKE_CURRENT_BINARY_DIR}/boost
  )

#WHY CAN'T IT EVER BE SMOOTH
if(WIN32)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/boost/include)
else(WIN32)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/boost/include/boost-1.52.0)
endif(WIN32)

if (MSVC60)
  set(BOOST_TOOLSET "vc6")
elseif(MSVC70)
  set(BOOST_TOOLSET "vc7")
elseif(MSVC71)
  set(BOOST_TOOLSET "vc71")
elseif(MSVC80)
  set(BOOST_TOOLSET "vc80")
elseif(MSVC90)
  set(BOOST_TOOLSET "vc90")
elseif(MSVC10)
  set(BOOST_TOOLSET "vc100")
elseif(MSVC11)
  set(BOOST_TOOLSET "vc110")
elseif(MSVC12)
  set(BOOST_TOOLSET "vc120")
elseif(MSVC14)
  set(BOOST_TOOLSET "vc140")
else(MSVC14)
  set(BOOST_TOOLSET "vc")
endif(MSVC60)

if(CMAKE_BUILD_TYPE MATCHES Debug)
  if(WIN32)
    #use .lib paths here
    set(Boost_LIBRARIES
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost_filesystem-${BOOST_TOOLSET}-mt-gd-1_52.lib
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost_date_time-${BOOST_TOOLSET}-mt-gd-1_52.lib
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost_program_options-${BOOST_TOOLSET}-mt-gd-1_52.lib
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost_system-${BOOST_TOOLSET}-mt-gd-1_52.lib
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost_thread-${BOOST_TOOLSET}-mt-gd-1_52.lib)
  else(WIN32)
      #use .a / .so paths here
      set(Boost_LIBRARIES
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost-1.52.0/libboost_program_options-mt-d.a
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost-1.52.0/libboost_system-mt-d.a
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost-1.52.0/libboost_date_time-mt-d.a
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost-1.52.0/libboost_filesystem-mt-d.a)
  endif(WIN32)
else(CMAKE_BUILD_TYPE MATCHES Debug)
  if(WIN32)
    #use .lib paths here
    set(Boost_LIBRARIES
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost_filesystem-${BOOST_TOOLSET}-mt-1_52.lib
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost_date_time-${BOOST_TOOLSET}-mt-1_52.lib
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost_program_options-${BOOST_TOOLSET}-mt-1_52.lib
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost_system-${BOOST_TOOLSET}-mt-1_52.lib
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost_thread-${BOOST_TOOLSET}-mt-1_52.lib)
  else(WIN32)
      #use .a / .so paths here
      set(Boost_LIBRARIES
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost-1.52.0/libboost_program_options-mt.a
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost-1.52.0/libboost_system-mt.a
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost-1.52.0/libboost_date_time-mt.a
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/boost-1.52.0/libboost_filesystem-mt.a)
  endif(WIN32)
endif(CMAKE_BUILD_TYPE MATCHES Debug)

if(WIN32)
SET(CMAKE_EXE_LINKER_FLAGS "/LARGEADDRESSAWARE ${CMAKE_EXE_LINKER_FLAGS}")
endif(WIN32)

add_subdirectory(llvm-3.5)
add_subdirectory(mc-sema)
