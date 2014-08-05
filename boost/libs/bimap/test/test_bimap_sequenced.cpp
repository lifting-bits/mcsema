// Boost.Bimap
//
// Copyright (c) 2006-2007 Matias Capeletto
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

//  VC++ 8.0 warns on usage of certain Standard Library and API functions that
//  can be cause buffer overruns or other possible security issues if misused.
//  See http://msdn.microsoft.com/msdnmag/issues/05/05/SafeCandC/default.aspx
//  But the wording of the warning is misleading and unsettling, there are no
//  portable alternative functions, and VC++ 8.0's own libraries use the
//  functions in question. So turn off the warnings.
#define _CRT_SECURE_NO_DEPRECATE
#define _SCL_SECURE_NO_DEPRECATE

#include <boost/config.hpp>

#define BOOST_BIMAP_DISABLE_SERIALIZATION

// Boost.Test
#include <boost/test/minimal.hpp>

// std
#include <set>
#include <map>
#include <algorithm>
#include <string>
#include <functional>


// Set type specifications
#include <boost/bimap/list_of.hpp>
#include <boost/bimap/vector_of.hpp>

// bimap container
#include <boost/bimap/bimap.hpp>
#include <boost/bimap/support/lambda.hpp>

#include <libs/bimap/test/test_bimap.hpp>

struct  left_tag {};
struct right_tag {};

void test_bimap()
{
    using namespace boost::bimaps;

    typedef std::map<std::string,long> left_data_type;
    left_data_type left_data;
    left_data.insert( left_data_type::value_type("1",1) );
    left_data.insert( left_data_type::value_type("2",2) );
    left_data.insert( left_data_type::value_type("3",3) );
    left_data.insert( left_data_type::value_type("4",4) );

    typedef std::map<long,std::string> right_data_type;
    right_data_type right_data;
    right_data.insert( right_data_type::value_type(1,"1") );
    right_data.insert( right_data_type::value_type(2,"2") );
    right_data.insert( right_data_type::value_type(3,"3") );
    right_data.insert( right_data_type::value_type(4,"4") );


    //--------------------------------------------------------------------
    {
        typedef bimap<
            list_of< std::string >, vector_of< long >

        > bm_type;

        std::set< bm_type::value_type > data;
        data.insert( bm_type::value_type("1",1) );
        data.insert( bm_type::value_type("2",2) );
        data.insert( bm_type::value_type("3",3) );
        data.insert( bm_type::value_type("4",4) );

        bm_type b;

        test_sequence_container(b,data);
        test_sequence_container(b.left , left_data);
        test_sequence_container(b.right,right_data);

        test_mapped_container(b.left );
        test_mapped_container(b.right);

        bm_type c;

        // Test assign

        b.clear();
        BOOST_CHECK( b.empty() );

        b.left.assign(left_data.begin(),left_data.end());
        BOOST_CHECK( b.size() == left_data.size() );

        b.right.assign(right_data.begin(),right_data.end());
        BOOST_CHECK( b.size() == right_data.size() );

        b.assign(data.begin(),data.end());
        BOOST_CHECK( b.size() == data.size() );

        // Test splice and merge

        b.clear();

        c.left.insert(c.left.begin(),left_data.begin(),left_data.end());
        b.left.splice(b.left.begin(),c.left);

        BOOST_CHECK( c.size() == 0 );
        BOOST_CHECK( b.size() == 4 );

        c.left.splice(c.left.begin(),b.left,++b.left.begin());

        BOOST_CHECK( c.size() == 1 );

        c.splice(c.begin(),b,b.begin(),b.end());

        BOOST_CHECK( b.size() == 0 );

        b.left.merge(c.left);
        c.left.merge(b.left,std::less<std::string>());

        b.left.sort();
        b.left.sort(std::less<std::string>());

        b.left.unique();
        b.left.unique(std::equal_to<std::string>());

        b.assign( data.begin(), data.end() );

        BOOST_CHECK( std::equal( b.begin(), b.end(), data.begin() ) );
        b.reverse();
        BOOST_CHECK( std::equal( b.rbegin(), b.rend(), data.begin() ) );

        b.sort();

        BOOST_CHECK( std::equal( b.begin(), b.end(), data.begin() ) );

        b.push_back( bm_type::value_type("4",4) );
        BOOST_CHECK( b.size() == 5 );
        b.unique();
        BOOST_CHECK( b.size() == 4 );
        b.remove_if( _key < bm_type::value_type("2",2) );
        BOOST_CHECK( b.size() == 3 );

        b.merge(c);

        b.left.remove_if( _key < "3" );

        // Test splice and merge

        b.clear(); c.clear();

        c.left.insert(c.left.begin(),left_data.begin(),left_data.end());
        b.right.splice(b.right.begin(),c.right);

        BOOST_CHECK( c.size() == 0 );
        BOOST_CHECK( b.size() == 4 );

        c.right.splice(c.right.begin(),b.right,++b.right.begin());

        b.right.merge(c.right);
        c.right.merge(b.right,std::less<long>());

        b.right.sort();
        b.right.sort(std::less<long>());

        b.right.unique();
        b.right.unique(std::equal_to<long>());

        b.right.remove_if( _key < 3 );

        b.clear();
        b.left.insert(b.left.begin(),left_data.begin(),left_data.end());

        b.left.relocate(b.left.begin(), ++b.left.begin() );
        b.left.relocate(b.left.end(), b.left.begin(), ++b.left.begin() );

        b.right.relocate(b.right.begin(), ++b.right.begin() );
        b.right.relocate(b.right.end(), b.right.begin(), ++b.right.begin() );

        b.relocate(b.begin(), ++b.begin() );
        b.relocate(b.end(), b.begin(), ++b.begin() );
    }
    //--------------------------------------------------------------------


    //--------------------------------------------------------------------
    {
        typedef bimap
        <
            list_of<std::string>, list_of<long>,
            vector_of_relation

        > bm_type;

        std::set< bm_type::value_type > data;
        data.insert( bm_type::value_type("1",1) );
        data.insert( bm_type::value_type("2",2) );
        data.insert( bm_type::value_type("3",3) );
        data.insert( bm_type::value_type("4",4) );

        bm_type b;
        b.push_back( bm_type::value_type("1",1) );
        b.push_back( bm_type::value_type("2",2) );
        b.push_back( bm_type::value_type("3",3) );
        b.push_back( bm_type::value_type("4",4) );

        BOOST_CHECK( std::equal( b.begin(), b.end(), data.begin() ) );
        b.reverse();
        BOOST_CHECK( std::equal( b.rbegin(), b.rend(), data.begin() ) );

        b.sort();

        BOOST_CHECK( std::equal( b.begin(), b.end(), data.begin() ) );

        b.push_back( bm_type::value_type("4",4) );
        BOOST_CHECK( b.size() == 5 );
        b.unique();
        BOOST_CHECK( b.size() == 4 );
        b.remove_if( _key < bm_type::value_type("2",2) );
        BOOST_CHECK( b.size() == 3 );

        b.relocate( b.begin(), ++b.begin() );
        b.relocate( b.end(), b.begin(), ++b.begin() );

        b.clear();
        BOOST_CHECK( b.empty() );

        b.left.assign(left_data.begin(),left_data.end());
        BOOST_CHECK( b.size() == left_data.size() );

        b.right.assign(right_data.begin(),right_data.end());
        BOOST_CHECK( b.size() == right_data.size() );

        b.assign(data.begin(),data.end());
        BOOST_CHECK( b.size() == data.size() );
    }
    //--------------------------------------------------------------------


    //--------------------------------------------------------------------
    {
        typedef bimap
        <
            vector_of< short >, list_of< short >,
            vector_of_relation

        > bimap_type;

        bimap_type b1;

        b1.push_back( bimap_type::value_type(1,2) );

        bimap_type b2( b1 );

        BOOST_CHECK(     b1 == b2   );
        BOOST_CHECK( ! ( b1 != b2 ) );
        BOOST_CHECK(     b1 <= b2   );
        BOOST_CHECK(     b1 >= b2   );
        BOOST_CHECK( ! ( b1 <  b2 ) );
        BOOST_CHECK( ! ( b1 >  b2 ) );

        b1.push_back( bimap_type::value_type(2,3) );

        b2 = b1;
        BOOST_CHECK( b2 == b1 );

        b1.push_back( bimap_type::value_type(3,4) );

        b2.left = b1.left;
        BOOST_CHECK( b2 == b1 );

        b1.push_back( bimap_type::value_type(4,5) );

        b2.right = b1.right;
        BOOST_CHECK( b2 == b1 );

        b1.clear();
        b2.swap(b1);
        BOOST_CHECK( b2.empty() && !b1.empty() );

        b1.left.swap( b2.left );
        BOOST_CHECK( b1.empty() && !b2.empty() );

        b1.right.swap( b2.right );
        BOOST_CHECK( b2.empty() && !b1.empty() );
    }
    //--------------------------------------------------------------------

}


int test_main( int, char* [] )
{
    test_bimap();
    return 0;
}

