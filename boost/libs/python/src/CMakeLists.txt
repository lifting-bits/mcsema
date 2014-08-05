#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
if (PYTHON_DEBUG_LIBRARIES AND BUILD_BOOST_PYTHON)
  # We have detected that there might be Python debug libraries
  # available, but check for ourselves whether this is true by trying
  # to compile/link a program against them.
  set(CMAKE_REQUIRED_DEFINITIONS "-DBOOST_DEBUG_PYTHON -DPy_DEBUG")
  get_directory_property(CMAKE_REQUIRED_INCLUDES INCLUDE_DIRECTORIES)
  set(CMAKE_REQUIRED_LIBRARIES ${PYTHON_DEBUG_LIBRARIES})
  set(CHECK_PYDEBUG_SOURCE
    "#include <boost/python/object.hpp>")
  check_cxx_source_compiles(
    "#include <boost/python/object.hpp>
    void check(PyObject *obj) { Py_INCREF(obj); } int main() { }" 
    PYDEBUG_CAN_BUILD)

  # Setup an option to enable/disable building variants with Python
  # debugging. If we were able to link against the debug libraries,
  # default to ON; otherwise, default to OFF.
  option(BUILD_PYTHON_DEBUG
    "Build an additional Boost.Python library with Python debugging enabled"
    ${PYDEBUG_CAN_BUILD})
endif (PYTHON_DEBUG_LIBRARIES AND BUILD_BOOST_PYTHON)

# Always build the non-debug variants of the boost_python library
set(BUILD_PYTHON_NODEBUG ON)

colormsg (GREEN "+-- BOOST_PYTHON_SUFFIX=${BOOST_PYTHON_SUFFIX}")
boost_add_library(python${BOOST_PYTHON_SUFFIX}
  numeric.cpp 
  list.cpp 
  long.cpp 
  dict.cpp 
  tuple.cpp 
  str.cpp 
  slice.cpp
  converter/from_python.cpp 
  converter/registry.cpp
  converter/type_id.cpp
  object/enum.cpp
  object/class.cpp
  object/function.cpp
  object/inheritance.cpp
  object/life_support.cpp
  object/pickle_support.cpp
  errors.cpp
  module.cpp
  converter/builtin_converters.cpp
  converter/arg_to_python_base.cpp
  object/iterator.cpp
  object/stl_iterator.cpp
  object_protocol.cpp
  object_operators.cpp
  wrapper.cpp
  import.cpp
  exec.cpp
  object/function_doc_signature.cpp

  STATIC_COMPILE_FLAGS "-DBOOST_PYTHON_SOURCE -DBOOST_PYTHON_STATIC_LIB"
  SHARED_COMPILE_FLAGS "-DBOOST_PYTHON_SOURCE"
  PYTHON_NODEBUG_LINK_LIBS "${PYTHON_LIBRARIES}"

  # Support for Python debugging
  EXTRA_VARIANTS PYTHON_NODEBUG:PYTHON_DEBUG
  PYTHON_DEBUG_COMPILE_FLAGS "-DBOOST_DEBUG_PYTHON -DPy_DEBUG"
  PYTHON_DEBUG_LINK_LIBS "${PYTHON_DEBUG_LIBRARIES}"
  )
