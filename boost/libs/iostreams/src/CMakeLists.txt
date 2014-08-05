#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
set(BOOST_IOSTREAMS_EXTRA_SOURCES)
set(BOOST_IOSTREAMS_LIBRARIES)

#
# These finds are done upstairs in libs/iostreams/CMakeLists.txt
#
if (ZLIB_FOUND)
  include_directories(${ZLIB_INCLUDE_DIR})
  set(ZLIB_EXTRA_SOURCES zlib.cpp gzip.cpp)
  set(ZLIB_EXTRA_LIBRARIES ${ZLIB_LIBRARIES})
endif(ZLIB_FOUND)

if (BZIP2_FOUND)
  include_directories(${BZIP2_INCLUDE_DIR})
  add_definitions(${BZIP2_DEFINITIONS})
  set(BZIP2_EXTRA_SOURCES bzip2.cpp)
  set(BZIP2_EXTRA_LIBRARIES ${BZIP2_LIBRARIES})
  # NOTE: What to do about BZIP2_NEED_PREFIX?
endif(BZIP2_FOUND)

boost_add_library(iostreams

  file_descriptor.cpp 
  mapped_file.cpp 
  ${ZLIB_EXTRA_SOURCES} 
  ${BZIP2_EXTRA_SOURCES}

  LINK_LIBS ${ZLIB_EXTRA_LIBRARIES} ${BZIP2_EXTRA_LIBRARIES}
  SHARED_COMPILE_FLAGS "-DBOOST_IOSTREAMS_DYN_LINK=1"
  )
