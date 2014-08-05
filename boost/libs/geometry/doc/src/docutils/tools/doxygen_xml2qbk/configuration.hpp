// Boost.Geometry (aka GGL, Generic Geometry Library)
//
// Copyright (c) 2010-2012 Barend Gehrels, Amsterdam, the Netherlands.
// Use, modification and distribution is subject to the Boost Software License,
// Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//
//
#ifndef CONFIGURATION_HPP
#define CONFIGURATION_HPP


#include <string>
#include <vector>


struct configuration
{
    // To transfer e.g. c:/_svn/boost/trunk/boost/geometry/algorithms/area.hpp
    // to #include <boost/geometry/...>
    // We need to find the position where the include path should start,
    // so fill out "boost" here, or "boost/geometry" (it uses rfind)
    std::string start_include;

    // Convenience headers (headefiles with solely purpose of including others
    std::string convenience_header_path;
    std::vector<std::string> convenience_headers;

    std::string skip_namespace;
};


#endif // CONFIGURATION_HPP
