#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
#----------------------------------------------------------------------------
# This file was automatically generated from the original CMakeLists.txt file
# Add a variable to hold the headers for the library
set (lib_headers
    asio.hpp
    asio
)

# Add a library target to the build system
boost_library_project(
  asio
  #  SRCDIRS 
  TESTDIRS test
  EXAMPLEDIRS
    example/ssl
    example/chat
    example/echo
    example/icmp
    example/http/server2
    example/http/server3
    example/http/server4
    example/http/client
    example/http/server
    example/local
    example/allocation
    example/porthopper
    example/invocation
    example/multicast
    example/serialization
    example/iostreams
    example/socks4
    example/timers
    example/tutorial/daytime1
    example/tutorial/daytime2
    example/tutorial/daytime3
    example/tutorial/daytime4
    example/tutorial/daytime5
    example/tutorial/daytime6
    example/tutorial/daytime7
    example/tutorial/timer1
    example/tutorial/timer2
    example/tutorial/timer3
    example/tutorial/timer4
    example/tutorial/timer5
    example/services
    example/timeouts
    example/windows
    example/nonblocking
    example/buffers
  HEADERS ${lib_headers}
  #  DOCDIRS 
  DESCRIPTION  "Portable networking, including sockets, timers, hostname resolution and socket iostreams."
  MODULARIZED
  AUTHORS  "Chris Kohlhoff <chris -at- kohlhoff.com>"
  #  MAINTAINERS 
)


