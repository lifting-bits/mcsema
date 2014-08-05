#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(gil BOOST_DEPENDS test lambda crc)


add_definitions(-DBOOST_GIL_NO_IO -D_SCL_SECURE_NO_WARNINGS)
boost_test_run(channel channel.cpp error_if.cpp)
boost_test_run(image image.cpp sample_image.cpp error_if.cpp
  ARGS ${CMAKE_CURRENT_SOURCE_DIR}/gil_reference_checksums.txt)
boost_test_run(image_io image_io.cpp error_if.cpp)
boost_test_run(pixel pixel.cpp error_if.cpp)
boost_test_run(pixel_iterator pixel_iterator.cpp error_if.cpp)
