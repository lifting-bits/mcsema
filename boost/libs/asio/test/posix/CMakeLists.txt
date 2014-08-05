#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
foreach(test
    basic_descriptor
    basic_stream_descriptor
    descriptor_base
    stream_descriptor
    stream_descriptor_service
    )
  asio_test_link(${test})
endforeach()


