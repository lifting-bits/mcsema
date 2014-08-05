// Boost.Range library
//
//  Copyright Thorsten Ottosen 2003-2004. Use, modification and
//  distribution is subject to the Boost Software License, Version
//  1.0. (See accompanying file LICENSE_1_0.txt or copy at
//  http://www.boost.org/LICENSE_1_0.txt)
//
// For more information, see http://www.boost.org/libs/range/
//
#include <boost/range/adaptor/tokenized.hpp>
#include <boost/range/algorithm_ext/push_back.hpp>
#include <boost/assert.hpp>
#include <algorithm>
#include <string>
#include <vector>

int main(int argc, const char* argv[])
{
    using namespace boost::adaptors;
    
    std::string input = " a b c d e f g hijklmnopqrstuvwxyz";
    std::vector< boost::sub_match< std::string::iterator > > result;
    boost::push_back(result, input | tokenized(boost::regex("\\b")));
    
    BOOST_ASSERT( boost::size(result) == 16u );
    
    return 0;
}
