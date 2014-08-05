#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_tool_project(bcp
  DESCRIPTION "The bcp utility is a tool for extracting subsets of Boost."
  AUTHORS "John Maddock"
  )

add_definitions(-DBOOST_REGEX_DYN_LINK=1 -DBOOST_TEST_NO_AUTO_LINK=1)

boost_add_executable( bcp

  add_path.cpp 
  bcp_imp.cpp 
  copy_path.cpp
  file_types.cpp
  fileview.cpp 
  main.cpp 
  path_operations.cpp 
  scan_cvs_path.cpp 
  licence_info.cpp 
  scan_licence.cpp 
  output_licence_info.cpp

  DEPENDS boost_system boost_filesystem boost_prg_exec_monitor boost_regex
  STATIC_COMPILE_FLAGS -DBOOST_SYSTEM_STATIC_LINK=1
  RELEASE
  STATIC
  )
