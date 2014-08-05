# Copyright (C) Troy Straszheim
#
# Distributed under the Boost Software License, Version 1.0. 
# See accompanying file LICENSE_1_0.txt or copy at 
#   http://www.boost.org/LICENSE_1_0.txt 
#
set(ICU_FIND_QUIETLY TRUE)
find_package(ICU)

boost_external_report(ICU INCLUDE_DIRS LIBRARIES I18N_LIBRARIES )

  
