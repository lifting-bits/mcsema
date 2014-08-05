#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
cmake_minimum_required(VERSION 2.6)

file(GLOB BOOST_EXPORTS "${BOOST_EXPORTS_DIR}/*.cmake")

foreach(import
    ${DEPENDS})
  include(${BOOST_EXPORTS_DIR}/${import}.cmake)
endforeach()

project(LinkTest)
include_directories (${INCLUDES})
add_executable(link-test ${SOURCE})
set_source_files_properties(${SOURCE}
  PROPERTIES COMPILE_FLAGS "${COMPILE_FLAGS}")

message("DEPENDS=====${DEPENDS}")

target_link_libraries(link-test
  ${LINK_LIBS}
  ${DEPENDS})
