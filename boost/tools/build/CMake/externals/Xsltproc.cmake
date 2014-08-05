# Copyright (C) Troy Straszheim
#
# Distributed under the Boost Software License, Version 1.0. 
# See accompanying file LICENSE_1_0.txt or copy at 
#   http://www.boost.org/LICENSE_1_0.txt 
#

# Find xsltproc to transform XML documents via XSLT
find_program(XSLTPROC_EXECUTABLE xsltproc DOC "xsltproc transforms XML via XSLT")

set(XSLTPROC_FLAGS "--xinclude" CACHE STRING 
  "Flags to pass to xsltproc to transform XML documents")
if(XSLTPROC_EXECUTABLE)
  set(XSLTPROC_FOUND TRUE)
endif()

boost_external_report(Xsltproc EXECUTABLE FLAGS) 
  
