#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(asio BOOST_DEPENDS test system)

set (dep_libs "")

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    set(dep_libs "pthread")
    set(os_defines "-D_XOPEN_SOURCE=600 -D_GNU_SOURCE=1")
endif(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")

if (${CMAKE_SYSTEM_NAME} STREQUAL "Solaris")
    set(dep_libs "socket;nsl")
    set(os_defines "-D_XOPEN_SOURCE=500 -D__EXTENSIONS__")
endif(${CMAKE_SYSTEM_NAME} STREQUAL "Solaris")

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    set(dep_libs "ws2_32;mswsock")
    set(os_defines "-D_WIN32_WINNT=0x0501")
endif(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")

if (CYGWIN)
    set(os_defines "-D__USE_W32_SOCKETS")
endif(CYGWIN)

if (${CMAKE_SYSTEM_NAME} STREQUAL "hpux")
    set(dep_libs "ipv6")
    set(os_defines "-D_XOPEN_SOURCE_EXTENDED")
endif(${CMAKE_SYSTEM_NAME} STREQUAL "hpux")

message(STATUS "!!!> missing some qnx stuff")

set (USE_SELECT "-DBOOST_ASIO_DISABLE_DEV_POLL -DBOOST_ASIO_DISABLE_EPOLL -DBOOST_ASIO_DISABLE_KQUEUE -DBOOST_ASIO_DISABLE_IOCP")

set (depends "boost_system-mt-static;boost_date_time-mt-static;boost_thread-mt-static")

set (os_defines "${os_defines} -DBOOST_ALL_NO_LIB=1")

macro(asio_test_run NAME)
  boost_test_run(${NAME} ${NAME}.cpp
    COMPILE_FLAGS "${os_defines}"
    LINK_LIBS "${dep_libs}"
    DEPENDS ${depends}
    )
  boost_test_run(${NAME}_select ${NAME}.cpp
    COMPILE_FLAGS "${os_defines} ${USE_SELECT}"
    LINK_LIBS "${dep_libs}"
    DEPENDS ${depends}
    )
endmacro(asio_test_run)

macro(asio_test_link NAME)
  boost_test_link(${NAME} ${NAME}.cpp
    COMPILE_FLAGS "${os_defines}"
    LINK_LIBS "${dep_libs}"
    DEPENDS "${depends}"
    )
  boost_test_link(${NAME}_select ${NAME}.cpp
    COMPILE_FLAGS "${os_defines} ${USE_SELECT}"
    LINK_LIBS "${dep_libs}"
    DEPENDS "${depends}"
    )
endmacro(asio_test_link)

foreach(test
    basic_datagram_socket
    basic_deadline_timer
    basic_socket_acceptor
    basic_stream_socket
    completion_condition
    datagram_socket_service
    deadline_timer_service
    socket_acceptor_service
    stream_socket_service
    time_traits
    )
  asio_test_link(${test})
endforeach()
    
foreach(test
    buffer
    buffered_read_stream
    buffered_stream
    buffered_write_stream
    buffers_iterator
    deadline_timer
    error
    io_service
    placeholders
    is_read_buffered
    is_write_buffered
    read
    read_at
    read_until
    socket_base
    strand
    write
    write_at
    )
    asio_test_run(${test})
endforeach()
    
add_subdirectory(ip)
add_subdirectory(local)
add_subdirectory(posix)

# Test Windows specific Behaviors
if (MSVC)
  foreach(test
      windows_basic_handle
      windows_basic_random_access_handle
      windows_basic_stream_handle
      windows_overlapped_ptr
      windows_random_access_handle
      windows_random_access_handle_service
      windows_stream_handle
      windows_stream_handle_service
      )
    boost_test_link(${test})
  endforeach()
endif (MSVC)

add_subdirectory(ssl)