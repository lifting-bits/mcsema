/* 
   Copyright (c) Marshall Clow 2011-2012.

   Distributed under the Boost Software License, Version 1.0. (See accompanying
   file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

    For more information, see http://www.boost.org
*/

#include <iostream>

#include <boost/config.hpp>
#include <boost/algorithm/cxx11/is_permutation.hpp>
#include <boost/test/included/test_exec_monitor.hpp>

#include <string>
#include <vector>
#include <list>

namespace ba = boost::algorithm;
// namespace ba = boost;

void test_sequence1 () {
    std::vector<int> v, v1;
    
    v.clear ();
    for ( std::size_t i = 5; i < 15; ++i )
        v.push_back ( i );
    v1 = v;
    BOOST_CHECK ( ba::is_permutation ( v.begin (), v.end (), v.begin ()));  // better be a permutation of itself!
    BOOST_CHECK ( ba::is_permutation ( v.begin (), v.end (), v1.begin ()));    

//  With bidirectional iterators.
    std::list<int> l;
    std::copy ( v.begin (), v.end (), std::back_inserter ( l ));
    BOOST_CHECK ( ba::is_permutation ( l.begin (), l.end (), l.begin ()));  // better be a permutation of itself!
    BOOST_CHECK ( ba::is_permutation ( l.begin (), l.end (), v1.begin ()));
    for ( std::size_t i = 0; i < l.size (); ++i ) {
        l.push_back ( *l.begin ()); l.pop_front (); // rotation
        BOOST_CHECK ( ba::is_permutation ( l.begin (), l.end (), v1.begin ()));
        }   
    }


int test_main( int , char* [] )
{
  test_sequence1 ();
  return 0;
}
