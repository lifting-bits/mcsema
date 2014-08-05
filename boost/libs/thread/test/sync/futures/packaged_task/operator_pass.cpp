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
// class packaged_task<R>

// void operator()();


#define BOOST_THREAD_VERSION 3
#include <boost/thread/future.hpp>
#include <boost/detail/lightweight_test.hpp>

class A
{
  long data_;

public:
  explicit A(long i) :
    data_(i)
  {
  }

  long operator()() const
  {
    return data_;
  }
  long operator()(long i, long j) const
  {
    if (j == 'z') throw A(6);
    return data_ + i + j;
  }
};

void func0(boost::packaged_task<double> p)
{
  boost::this_thread::sleep_for(boost::chrono::milliseconds(500));
  //p(3, 'a');
  p();
}

void func1(boost::packaged_task<double(int, char)> p)
{
  boost::this_thread::sleep_for(boost::chrono::milliseconds(500));
  //p(3, 'z');
  p();
}

void func2(boost::packaged_task<double(int, char)> p)
{
  //p(3, 'a');
  p();
  try
  {
    //p(3, 'c');
    p();
  }
  catch (const boost::future_error& e)
  {
    BOOST_TEST(e.code() == make_error_code(boost::future_errc::promise_already_satisfied));
  }
}

void func3(boost::packaged_task<double(int, char)> p)
{
  try
  {
    //p(3, 'a');
    p();
  }
  catch (const boost::future_error& e)
  {
    BOOST_TEST(e.code() == make_error_code(boost::future_errc::no_state));
  }
}

int main()
{
  {
    boost::packaged_task<double> p(A(5));
    boost::future<double> f = BOOST_THREAD_MAKE_RV_REF(p.get_future());
    boost::thread(func0, boost::move(p)).detach();
    BOOST_TEST(f.get() == 5.0);
  }
  {
    boost::packaged_task<double> p(A(5));
    boost::future<double> f = BOOST_THREAD_MAKE_RV_REF(p.get_future());
    boost::thread(func1, boost::move(p)).detach();
    try
    {
      f.get();
      BOOST_TEST(false);
    }
    catch (const A& e)
    {
      //BOOST_TEST(e(3, 'a') == 106);
      BOOST_TEST(e() == 5);
    }
  }
  {
    boost::packaged_task<double> p(A(5));
    boost::future<double> f = BOOST_THREAD_MAKE_RV_REF(p.get_future());
    boost::thread t(func2, boost::move(p));
    BOOST_TEST(f.get() == 5.0);
    t.join();
  }
  {
    boost::packaged_task<double> p;
    boost::thread t(func3, boost::move(p));
    t.join();
  }

  return boost::report_errors();
}

