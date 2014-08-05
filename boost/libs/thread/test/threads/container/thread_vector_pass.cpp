// Copyright (C) 2011 Vicente J. Botet Escriba
//
//  Distributed under the Boost Software License, Version 1.0. (See accompanying
//  file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#define BOOST_THREAD_USES_MOVE

#include <boost/thread/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/container/vector.hpp>
#include <iostream>
#include <boost/detail/lightweight_test.hpp>

int count = 0;
boost::mutex mutex;

namespace
{
template <typename TC>
void join_all(TC & tc)
{
  for (typename TC::iterator it = tc.begin(); it != tc.end(); ++it)
  {
    it->join();
  }
}

template <typename TC>
void interrupt_all(TC & tc)
{
  for (typename TC::iterator it = tc.begin(); it != tc.end(); ++it)
  {
    it->interrupt();
  }
}
}

void increment_count()
{
  boost::mutex::scoped_lock lock(mutex);
  std::cout << "count = " << ++count << std::endl;
}

int main()
{
  typedef boost::container::vector<boost::thread> thread_vector;
  {
    thread_vector threads;
    threads.reserve(10);
    for (int i = 0; i < 10; ++i)
    {
      boost::thread th(&increment_count);
      threads.push_back(boost::move(th));
    }
    join_all(threads);
  }
  count = 0;
  {
    thread_vector threads;
    threads.reserve(10);
    for (int i = 0; i < 10; ++i)
    {
      threads.push_back(BOOST_THREAD_MAKE_RV_REF(boost::thread(&increment_count)));
    }
    join_all(threads);
  }
  count = 0;
  {
    thread_vector threads;
    threads.reserve(10);
    for (int i = 0; i < 10; ++i)
    {
      threads.emplace_back(&increment_count);
    }
    join_all(threads);
  }
  count = 0;
  {
    thread_vector threads;
    threads.reserve(10);
    for (int i = 0; i < 10; ++i)
    {
      threads.emplace_back(&increment_count);
    }
    interrupt_all(threads);
  }
  return boost::report_errors();
}
