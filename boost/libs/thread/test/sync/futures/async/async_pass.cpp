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

// template <class F, class... Args>
//     future<typename result_of<F(Args...)>::type>
//     async(F&& f, Args&&... args);

// template <class F, class... Args>
//     future<typename result_of<F(Args...)>::type>
//     async(launch policy, F&& f, Args&&... args);

#define BOOST_THREAD_VERSION 3

#include <boost/thread/future.hpp>
#include <boost/thread/thread.hpp>
#include <boost/interprocess/smart_ptr/unique_ptr.hpp>
#include <memory>
#include <boost/detail/lightweight_test.hpp>

typedef boost::chrono::high_resolution_clock Clock;
typedef boost::chrono::milliseconds ms;

class A
{
    long data_;

public:
    typedef int result_type;

    explicit A(long i) : data_(i) {}

    long operator()() const
    {
      boost::this_thread::sleep_for(ms(200));
      return data_;
    }
};

class MoveOnly
{
public:
  typedef int result_type;

  BOOST_THREAD_MOVABLE_ONLY(MoveOnly)
  MoveOnly()
  {
  }
  MoveOnly(BOOST_THREAD_RV_REF(MoveOnly))
  {}

  int operator()()
  {
    boost::this_thread::sleep_for(ms(200));
    return 3;
  }
};

int f0()
{
  boost::this_thread::sleep_for(ms(200));
  return 3;
}

int i = 0;

int& f1()
{
  boost::this_thread::sleep_for(ms(200));
  return i;
}

void f2()
{
  boost::this_thread::sleep_for(ms(200));
}

boost::interprocess::unique_ptr<int, boost::default_delete<int> > f3(int i)
{
  boost::this_thread::sleep_for(ms(200));
  return boost::interprocess::unique_ptr<int, boost::default_delete<int> >(new int(i));
}

typedef boost::interprocess::unique_ptr<int, boost::default_delete<int> > XXT;
boost::interprocess::unique_ptr<int, boost::default_delete<int> > f4(
    BOOST_THREAD_RV_REF(boost::interprocess::unique_ptr<int, boost::default_delete<int> > ) p)
{
  boost::this_thread::sleep_for(ms(200));
  return boost::move(p);
}


int main()
{
  {
    boost::future<int> f = boost::async(f0);
    boost::this_thread::sleep_for(ms(300));
    Clock::time_point t0 = Clock::now();
    BOOST_TEST(f.get() == 3);
    Clock::time_point t1 = Clock::now();
    BOOST_TEST(t1 - t0 < ms(100));
  }
  {
    boost::future<int> f = boost::async(boost::launch::async, f0);
    boost::this_thread::sleep_for(ms(300));
    Clock::time_point t0 = Clock::now();
    BOOST_TEST(f.get() == 3);
    Clock::time_point t1 = Clock::now();
    BOOST_TEST(t1 - t0 < ms(100));
  }
  {
    boost::future<int> f = boost::async(boost::launch::async, A(3));
    boost::this_thread::sleep_for(ms(300));
    Clock::time_point t0 = Clock::now();
    BOOST_TEST(f.get() == 3);
    Clock::time_point t1 = Clock::now();
    BOOST_TEST(t1 - t0 < ms(100));
  }
  {
    boost::future<int> f = boost::async(boost::launch::async, BOOST_THREAD_MAKE_RV_REF(MoveOnly()));
    boost::this_thread::sleep_for(ms(300));
    Clock::time_point t0 = Clock::now();
    BOOST_TEST(f.get() == 3);
    Clock::time_point t1 = Clock::now();
    BOOST_TEST(t1 - t0 < ms(100));
  }
  {
    boost::future<int> f = boost::async(boost::launch::any, f0);
    boost::this_thread::sleep_for(ms(300));
    Clock::time_point t0 = Clock::now();
    BOOST_TEST(f.get() == 3);
    Clock::time_point t1 = Clock::now();
    BOOST_TEST(t1 - t0 < ms(100));
  }
//  {
//    boost::future<int> f = boost::async(boost::launch::deferred, f0);
//    boost::this_thread::sleep_for(ms(300));
//    Clock::time_point t0 = Clock::now();
//    BOOST_TEST(f.get() == 3);
//    Clock::time_point t1 = Clock::now();
//    BOOST_TEST(t1 - t0 > ms(100));
//  }
//
  {
    boost::future<int&> f = boost::async(f1);
    boost::this_thread::sleep_for(ms(300));
    Clock::time_point t0 = Clock::now();
    BOOST_TEST(&f.get() == &i);
    Clock::time_point t1 = Clock::now();
    BOOST_TEST(t1 - t0 < ms(100));
  }
  {
    boost::future<int&> f = boost::async(boost::launch::async, f1);
    boost::this_thread::sleep_for(ms(300));
    Clock::time_point t0 = Clock::now();
    BOOST_TEST(&f.get() == &i);
    Clock::time_point t1 = Clock::now();
    BOOST_TEST(t1 - t0 < ms(100));
  }
  {
    boost::future<int&> f = boost::async(boost::launch::any, f1);
    boost::this_thread::sleep_for(ms(300));
    Clock::time_point t0 = Clock::now();
    BOOST_TEST(&f.get() == &i);
    Clock::time_point t1 = Clock::now();
    BOOST_TEST(t1 - t0 < ms(100));
  }
//  {
//    boost::future<int&> f = boost::async(boost::launch::deferred, f1);
//    boost::this_thread::sleep_for(ms(300));
//    Clock::time_point t0 = Clock::now();
//    BOOST_TEST(&f.get() == &i);
//    Clock::time_point t1 = Clock::now();
//    BOOST_TEST(t1 - t0 > ms(100));
//  }
//
  {
    boost::future<void> f = boost::async(f2);
    boost::this_thread::sleep_for(ms(300));
    Clock::time_point t0 = Clock::now();
    f.get();
    Clock::time_point t1 = Clock::now();
    BOOST_TEST(t1 - t0 < ms(100));
  }
  {
    boost::future<void> f = boost::async(boost::launch::async, f2);
    boost::this_thread::sleep_for(ms(300));
    Clock::time_point t0 = Clock::now();
    f.get();
    Clock::time_point t1 = Clock::now();
    BOOST_TEST(t1 - t0 < ms(100));
  }
  {
    boost::future<void> f = boost::async(boost::launch::any, f2);
    boost::this_thread::sleep_for(ms(300));
    Clock::time_point t0 = Clock::now();
    f.get();
    Clock::time_point t1 = Clock::now();
    BOOST_TEST(t1 - t0 < ms(100));
  }
//  {
//    boost::future<void> f = boost::async(boost::launch::deferred, f2);
//    boost::this_thread::sleep_for(ms(300));
//    Clock::time_point t0 = Clock::now();
//    f.get();
//    Clock::time_point t1 = Clock::now();
//    BOOST_TEST(t1 - t0 > ms(100));
//  }

//  {
//    boost::future<boost::interprocess::unique_ptr<int, boost::default_delete<int> > > f = boost::async(f3, 3);
//    boost::this_thread::sleep_for(ms(300));
//    Clock::time_point t0 = Clock::now();
//    BOOST_TEST(*f.get() == 3);
//    Clock::time_point t1 = Clock::now();
//    BOOST_TEST(t1 - t0 < ms(100));
//  }

//  {
//    boost::future<boost::interprocess::unique_ptr<int, boost::default_delete<int> > > f = boost::async(f4, boost::interprocess::unique_ptr<int, boost::default_delete<int> >(new int(3)));
//    boost::this_thread::sleep_for(ms(300));
//    Clock::time_point t0 = Clock::now();
//    BOOST_TEST(*f.get() == 3);
//    Clock::time_point t1 = Clock::now();
//    BOOST_TEST(t1 - t0 < ms(100));
//  }
  return boost::report_errors();
}

