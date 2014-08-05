# Copyright (C) Troy Straszheim
#
# Distributed under the Boost Software License, Version 1.0. 
# See accompanying file LICENSE_1_0.txt or copy at 
#   http://www.boost.org/LICENSE_1_0.txt 
#

# Find xsltproc to transform XML documents via XSLT
find_program(VALGRIND_EXECUTABLE valgrind DOC "Valgrind executable")

set(VALGRIND_FLAGS "--tool=memcheck" CACHE STRING 
  "Flags to pass to xsltproc to transform XML documents")
if(VALGRIND_EXECUTABLE)
  set(VALGRIND_FOUND TRUE CACHE BOOL "Valgrind found" FORCE)
endif()

boost_external_report(Valgrind EXECUTABLE FLAGS)
  
