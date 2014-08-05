/* Boost.MultiIndex test for capacity memfuns.
 *
 * Copyright 2003-2008 Joaquin M Lopez Munoz.
 * Distributed under the Boost Software License, Version 1.0.
 * (See accompanying file LICENSE_1_0.txt or copy at
 * http://www.boost.org/LICENSE_1_0.txt)
 *
 * See http://www.boost.org/libs/multi_index for library home page.
 */

#include "test_capacity.hpp"

#include <boost/config.hpp> /* keep it first to prevent nasty warns in MSVC */
#include "pre_multi_index.hpp"
#include "employee.hpp"
#include <boost/test/test_tools.hpp>

using namespace boost::multi_index;

void test_capacity()
{
  employee_set es;

  es.insert(employee(0,"Joe",31,1123));
  es.insert(employee(1,"Robert",27,5601));
  es.insert(employee(2,"John",40,7889));
  es.insert(employee(3,"Albert",20,9012));
  es.insert(employee(4,"John",57,1002));

  BOOST_CHECK(!es.empty());
  BOOST_CHECK(es.size()==5);
  BOOST_CHECK(es.size()<=es.max_size());

  es.erase(es.begin());
  BOOST_CHECK(!get<name>(es).empty());
  BOOST_CHECK(get<name>(es).size()==4);
  BOOST_CHECK(get<name>(es).size()<=get<name>(es).max_size());

  es.erase(es.begin());
  BOOST_CHECK(!get<as_inserted>(es).empty());
  BOOST_CHECK(get<as_inserted>(es).size()==3);
  BOOST_CHECK(get<as_inserted>(es).size()<=get<as_inserted>(es).max_size());

  multi_index_container<int,indexed_by<sequenced<> > > ss;

  ss.resize(10);
  BOOST_CHECK(ss.size()==10);
  BOOST_CHECK(ss.size()<=ss.max_size());

  ss.resize(20);
  BOOST_CHECK(ss.size()==20);

  ss.resize(5);
  BOOST_CHECK(ss.size()==5);

  ss.resize(4);
  BOOST_CHECK(ss.size()==4);

  multi_index_container<int,indexed_by<random_access<> > > rs;

  rs.resize(10);
  BOOST_CHECK(rs.size()==10);
  BOOST_CHECK(rs.size()<=rs.max_size());
  BOOST_CHECK(rs.size()<=rs.capacity());

  rs.resize(20);
  BOOST_CHECK(rs.size()==20);
  BOOST_CHECK(rs.size()<=rs.capacity());

  unsigned int c=rs.capacity();
  rs.resize(5);
  BOOST_CHECK(rs.size()==5);
  BOOST_CHECK(rs.capacity()==c);

  rs.reserve(100);
  BOOST_CHECK(rs.size()==5);
  BOOST_CHECK(rs.capacity()>=100);

  c=rs.capacity();
  rs.reserve(99);
  BOOST_CHECK(rs.size()==5);
  BOOST_CHECK(rs.capacity()==c);
}
