// Boost.Range library
//
//  Copyright Thorsten Ottosen 2003-2004. Use, modification and
//  distribution is subject to the Boost Software License, Version
//  1.0. (See accompanying file LICENSE_1_0.txt or copy at
//  http://www.boost.org/LICENSE_1_0.txt)
//
// For more information, see http://www.boost.org/libs/range/
//
#include <boost/range/adaptor/indexed.hpp>
#include <boost/range/algorithm/copy.hpp>
#include <boost/assign.hpp>
#include <algorithm>
#include <iostream>
#include <vector>

template<typename Iterator>
void display_element_and_index(Iterator first, Iterator last)
{
    for (Iterator it = first; it != last; ++it)
    {
        std::cout << "Element = " << *it
                  << " Index = " << it.index() << std::endl;
    }
}

template<typename SinglePassRange>
void display_element_and_index(const SinglePassRange& rng)
{
    display_element_and_index(boost::begin(rng), boost::end(rng));
}

int main(int argc, const char* argv[])
{
    using namespace boost::assign;
    using namespace boost::adaptors;
    
    std::vector<int> input;
    input += 10,20,30,40,50,60,70,80,90;
    
    display_element_and_index( input | indexed(0) );
    
    return 0;
}

