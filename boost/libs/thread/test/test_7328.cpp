// Copyright (C) 2010 Vicente Botet
//
//  Distributed under the Boost Software License, Version 1.0. (See accompanying
//  file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <iostream>
#include <boost/thread.hpp>
#include <boost/detail/lightweight_test.hpp>

//using namespace boost;
using namespace boost::chrono;

bool interrupted = false;
void f()
{
  try
  {
    std::cout << "Starting sleep in thread" << std::endl;
    while (true)
    {
      boost::this_thread::sleep_for(seconds(60));
    }
  }
  catch (const boost::thread_interrupted&)
  {
    interrupted = true;
    std::cout << "Thread interrupted." << std::endl;
  }
}

int main()
{
  boost::thread t(f);
  t.interrupt();
  t.join();
  std::cout << "Joined with thread." << std::endl;
  BOOST_TEST(interrupted);
  return boost::report_errors();
}
