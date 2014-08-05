//  Boost string_algo library iterator_test.cpp file  ---------------------------//

//  Copyright Pavol Droba 2002-2003. Use, modification and
//  distribution is subject to the Boost Software License, Version
//  1.0. (See accompanying file LICENSE_1_0.txt or copy at
//  http://www.boost.org/LICENSE_1_0.txt)

//  See http://www.boost.org for updates, documentation, and revision history.

#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
// equals predicate is used for result comparison
#include <boost/algorithm/string/predicate.hpp>

// Include unit test framework
#include <boost/test/included/test_exec_monitor.hpp>

#include <string>
#include <vector>
#include <iostream>

#include <boost/test/test_tools.hpp>


using namespace std;
using namespace boost;

template< typename T1, typename T2 >
void deep_compare( const T1& X, const T2& Y )
{
    BOOST_REQUIRE( X.size() == Y.size() );
    for( unsigned int nIndex=0; nIndex<X.size(); ++nIndex )
    {
        BOOST_CHECK( equals( X[nIndex], Y[nIndex] ) );
    }
}

void iterator_test()
{
    string str1("xx-abc--xx-abb");
    string str2("Xx-abc--xX-abb-xx");
    string str3("xx");
    string strempty("");
    const char* pch1="xx-abc--xx-abb";
    vector<string> tokens;
    vector< vector<int> > vtokens;

    // find_all tests
    find_all(
        tokens,
        pch1,
        "xx" );

    BOOST_REQUIRE( tokens.size()==2 );
    BOOST_CHECK( tokens[0]==string("xx") );
    BOOST_CHECK( tokens[1]==string("xx") );

    ifind_all(
        tokens,
        str2,
        "xx" );

    BOOST_REQUIRE( tokens.size()==3 );
    BOOST_CHECK( tokens[0]==string("Xx") );
    BOOST_CHECK( tokens[1]==string("xX") );
    BOOST_CHECK( tokens[2]==string("xx") );

    find_all(
        tokens,
        str1,
        "xx" );

    BOOST_REQUIRE( tokens.size()==2 );
    BOOST_CHECK( tokens[0]==string("xx") );
    BOOST_CHECK( tokens[1]==string("xx") );

    find_all(
        vtokens,
        str1,
        string("xx") );
    deep_compare( tokens, vtokens );

    // split tests
    split(
        tokens,
        str2,
        is_any_of("xX"),
        token_compress_on );

    BOOST_REQUIRE( tokens.size()==4 );
    BOOST_CHECK( tokens[0]==string("") );
    BOOST_CHECK( tokens[1]==string("-abc--") );
    BOOST_CHECK( tokens[2]==string("-abb-") );
    BOOST_CHECK( tokens[3]==string("") );

    split(
        tokens,
        pch1,
        is_any_of("x"),
        token_compress_on );

    BOOST_REQUIRE( tokens.size()==3 );
    BOOST_CHECK( tokens[0]==string("") );
    BOOST_CHECK( tokens[1]==string("-abc--") );
    BOOST_CHECK( tokens[2]==string("-abb") );

    split(
        vtokens,
        str1,
        is_any_of("x"),
        token_compress_on );
    deep_compare( tokens, vtokens );

    split(
        tokens,
        str1,
        is_punct(),
        token_compress_off );

    BOOST_REQUIRE( tokens.size()==5 );
    BOOST_CHECK( tokens[0]==string("xx") );
    BOOST_CHECK( tokens[1]==string("abc") );
    BOOST_CHECK( tokens[2]==string("") );
    BOOST_CHECK( tokens[3]==string("xx") );
    BOOST_CHECK( tokens[4]==string("abb") );

    split(
        tokens,
        str3,
        is_any_of(","),
        token_compress_off);

    BOOST_REQUIRE( tokens.size()==1 );
    BOOST_CHECK( tokens[0]==string("xx") );

    split(
        tokens,
        strempty,
        is_punct(),
        token_compress_off);

    BOOST_REQUIRE( tokens.size()==1 );
    BOOST_CHECK( tokens[0]==string("") );


    find_iterator<string::iterator> fiter=make_find_iterator(str1, first_finder("xx"));
    BOOST_CHECK(equals(*fiter, "xx"));
    ++fiter;
    BOOST_CHECK(equals(*fiter, "xx"));
    ++fiter;
    BOOST_CHECK(fiter==find_iterator<string::iterator>());

    split_iterator<string::iterator> siter=make_split_iterator(str1, token_finder(is_any_of("-"), token_compress_on));
    BOOST_CHECK(equals(*siter, "xx"));
    ++siter;
    BOOST_CHECK(equals(*siter, "abc"));
    ++siter;
    BOOST_CHECK(equals(*siter, "xx"));
    ++siter;
    BOOST_CHECK(equals(*siter, "abb"));
    ++siter;
    BOOST_CHECK(siter==split_iterator<string::iterator>(siter));
    BOOST_CHECK(siter==split_iterator<string::iterator>());

}

// test main 
int test_main( int, char*[] )
{
    iterator_test();
    
    return 0;
}
