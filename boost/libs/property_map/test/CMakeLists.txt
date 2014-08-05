# Copyright (C) 2008 Michael Jackson
#
# Use, modification and distribution is subject to the Boost Software
# License, Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt)

boost_additional_test_dependencies(property_map BOOST_DEPENDS test concept_check any)

boost_test_compile(property_map_cc)

boost_test_run(dynamic_properties_test)
