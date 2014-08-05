#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
foreach(test
    basic_endpoint
    connect_pair
    datagram_protocol
    stream_protocol
    )
  asio_test_link(${test})
endforeach()


