#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_tool_project(Inspect
  DESCRIPTION "Boost inspector tool")

boost_tool_dependencies(BOOST_DEPENDS filesystem system regex test)

boost_add_executable(inspect 

  inspect.cpp license_check.cpp
  link_check.cpp path_name_check.cpp tab_check.cpp crlf_check.cpp
  end_check.cpp unnamed_namespace_check.cpp ascii_check.cpp
  copyright_check.cpp minmax_check.cpp 

  DEPENDS boost_filesystem boost_system boost_regex
  )
