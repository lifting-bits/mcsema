/* 
   Copyright (c) Marshall Clow 2012.

   Distributed under the Boost Software License, Version 1.0. (See accompanying
   file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

    For more information, see http://www.boost.org
*/

#include <boost/config.hpp>
#include <boost/algorithm/cxx11/copy_if.hpp>
#include <boost/test/included/test_exec_monitor.hpp>

#include <algorithm>
#include <string>
#include <iostream>
#include <vector>
#include <list>

#include <boost/algorithm/cxx11/all_of.hpp>

namespace ba = boost::algorithm;
// namespace ba = boost;

bool is_true  ( int v ) { return true; }
bool is_false ( int v ) { return false; }
bool is_even  ( int v ) { return v % 2 == 0; }
bool is_odd   ( int v ) { return v % 2 == 1; }

template <typename Container>
void test_sequence ( Container const &c ) {

    typedef typename Container::value_type value_type;
    std::vector<value_type> v;
    
//  None of the elements
    v.clear ();
    ba::copy_if ( c.begin (), c.end (), back_inserter ( v ), is_false);
    BOOST_CHECK ( v.size () == 0 );

    v.clear ();
    ba::copy_if ( c, back_inserter ( v ), is_false);
    BOOST_CHECK ( v.size () == 0 );

//	All the elements
    v.clear ();
    ba::copy_if ( c.begin (), c.end (), back_inserter ( v ), is_true);
    BOOST_CHECK ( v.size () == c.size ());
    BOOST_CHECK ( std::equal ( c.begin (), c.end (), v.begin ()));

    v.clear ();
    ba::copy_if ( c, back_inserter ( v ), is_true);
    BOOST_CHECK ( v.size () == c.size ());
    BOOST_CHECK ( v.size () == c.size ());
    BOOST_CHECK ( std::equal ( c.begin (), c.end (), v.begin ()));

//	Some of the elements
    v.clear ();
    ba::copy_if ( c.begin (), c.end (), back_inserter ( v ), is_even );
    BOOST_CHECK ( v.size () == std::count_if ( c.begin (), c.end (), is_even ));
    BOOST_CHECK ( ba::all_of ( v.begin (), v.end (), is_even ));

    v.clear ();
    ba::copy_if ( c, back_inserter ( v ), is_even );
    BOOST_CHECK ( v.size () == std::count_if ( c.begin (), c.end (), is_even ));
    BOOST_CHECK ( ba::all_of ( v.begin (), v.end (), is_even ));
    }


void test_sequence1 () {
    std::vector<int> v;
    for ( int i = 5; i < 15; ++i )
        v.push_back ( i );
    test_sequence  ( v );
    
    std::list<int> l;
    for ( int i = 25; i > 15; --i )
        l.push_back ( i );
    test_sequence  ( l );   
    }


int test_main( int , char* [] )
{
  test_sequence1 ();
  return 0;
}
