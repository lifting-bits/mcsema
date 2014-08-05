//===----------------------------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is dual licensed under the MIT and the University of Illinois Open
// Source Licenses. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

// Copyright (C) 2011 Vicente J. Botet Escriba
//
//  Distributed under the Boost Software License, Version 1.0. (See accompanying
//  file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

// <boost/thread/future.hpp>

// class promise<R>

// future<R> get_future();

#define BOOST_THREAD_VERSION 3

#include <boost/thread/future.hpp>
#include <boost/thread/thread.hpp>
#include <boost/detail/lightweight_test.hpp>

namespace boost
{
template <typename T>
struct wrap
{
  wrap(T const& v) : value(v){}
  T value;

};

template <typename T>
exception_ptr make_exception_ptr(T v) {
  return copy_exception(wrap<T>(v));
}
}

void func1(boost::promise<int> p)
{
    boost::this_thread::sleep_for(boost::chrono::milliseconds(500));
    p.set_value(3);
}

void func2(boost::promise<int> p)
{
    boost::this_thread::sleep_for(boost::chrono::milliseconds(500));
    p.set_exception(boost::make_exception_ptr(3));
}

int j = 0;

void func3(boost::promise<int&> p)
{
    boost::this_thread::sleep_for(boost::chrono::milliseconds(500));
    j = 5;
    p.set_value(j);
}

void func4(boost::promise<int&> p)
{
    boost::this_thread::sleep_for(boost::chrono::milliseconds(500));
    p.set_exception(boost::make_exception_ptr(3.5));
}

void func5(boost::promise<void> p)
{
    boost::this_thread::sleep_for(boost::chrono::milliseconds(500));
    p.set_value();
}

void func6(boost::promise<void> p)
{
    boost::this_thread::sleep_for(boost::chrono::milliseconds(500));
    p.set_exception(boost::make_exception_ptr('c'));
}


int main()
{
  {
      typedef int T;
      {
          boost::promise<T> p;
          boost::future<T> f = p.get_future();
          boost::thread(func1, boost::move(p)).detach();
          BOOST_TEST(f.valid());
          BOOST_TEST(f.get() == 3);
          BOOST_TEST(!f.valid());
      }
      {
          boost::promise<T> p;
          boost::future<T> f = p.get_future();
          boost::thread(func2, boost::move(p)).detach();
          try
          {
              BOOST_TEST(f.valid());
              BOOST_TEST(f.get() == 3);
              BOOST_TEST(false);
          }
          catch (int i)
          {
              BOOST_TEST(i == 3);
          }
          BOOST_TEST(!f.valid());
      }
  }
//  {
//      typedef int& T;
//      {
//          boost::promise<T> p;
//          boost::future<T> f = p.get_future();
//          boost::thread(func3, boost::move(p)).detach();
//          BOOST_TEST(f.valid());
//          BOOST_TEST(f.get() == 5);
//          BOOST_TEST(!f.valid());
//      }
//      {
//          boost::promise<T> p;
//          boost::future<T> f = p.get_future();
//          boost::thread(func4, boost::move(p)).detach();
//          try
//          {
//              BOOST_TEST(f.valid());
//              BOOST_TEST(f.get() == 3);
//              BOOST_TEST(false);
//          }
//          catch (double i)
//          {
//              BOOST_TEST(i == 3.5);
//          }
//          BOOST_TEST(!f.valid());
//      }
//  }
//  {
//      typedef void T;
//      {
//          boost::promise<T> p;
//          boost::future<T> f = p.get_future();
//          boost::thread(func5, boost::move(p)).detach();
//          BOOST_TEST(f.valid());
//          f.get();
//          BOOST_TEST(!f.valid());
//      }
//      {
//          boost::promise<T> p;
//          boost::future<T> f = p.get_future();
//          boost::thread(func6, boost::move(p)).detach();
//          try
//          {
//              BOOST_TEST(f.valid());
//              f.get();
//              BOOST_TEST(false);
//          }
//          catch (char i)
//          {
//              BOOST_TEST(i == 'c');
//          }
//          BOOST_TEST(!f.valid());
//      }
//  }



  return boost::report_errors();
}

