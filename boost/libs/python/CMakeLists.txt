#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
if (PYTHON_FOUND)
  include_directories(${PYTHON_INCLUDE_PATH})

  boost_library_project(
    Python
    SRCDIRS src
    TESTDIRS test
    HEADERS python.hpp python
    MODULARIZED
    DESCRIPTION "A framework for interfacing Python and C++. It allows you to quickly and seamlessly expose C++ classes functions and objects to Python, and vice-versa, using no special tools -- just your C++ compiler."
    AUTHORS "David Abrahams <dave -at- boostpro.com>"
    )
else ()
  colormsg(RED "+-- disabled since PYTHON_FOUND is false")
endif ()
