// Copyright (C) 2010 Vicente Botet
//
//  Distributed under the Boost Software License, Version 1.0. (See accompanying
//  file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <boost/test/unit_test.hpp>

#include <iostream>

#include <boost/thread.hpp>

  using namespace std;

  boost::mutex mutex_;

  void perform()
  {
     try
     {
        boost::this_thread::sleep(boost::posix_time::seconds(100));
     }
     catch (boost::thread_interrupted& interrupt)
     {
        boost::mutex::scoped_lock lock(mutex_);
        cerr << "Thread " << boost::this_thread::get_id() << " got interrupted" << endl;
        throw(interrupt);
     }
     catch (std::exception& e)
     {
        boost::mutex::scoped_lock lock(mutex_);
        cerr << "Thread " << boost::this_thread::get_id() << " caught std::exception" << e.what() << endl;
     }
     catch (...)
     {
        boost::mutex::scoped_lock lock(mutex_);
        cerr << "Thread " << boost::this_thread::get_id() << " caught something else" << endl;
     }
  }

  void test()
  {
    try
    {
    boost::thread_group threads;

     for (int i = 0; i < 2; ++i)
     {
        threads.create_thread(perform);
     }

     //boost::this_thread::sleep(1);
     threads.interrupt_all();
     threads.join_all();
    }
    catch (...)
    {
      BOOST_CHECK(false && "exception raised");
    }
  }

boost::unit_test_framework::test_suite* init_unit_test_suite(int, char*[])
{
    boost::unit_test_framework::test_suite* tests =
        BOOST_TEST_SUITE("Boost.Threads: 2309");

    tests->add(BOOST_TEST_CASE(&test));

    return tests;
}

void remove_unused_warning()
{

  //../../../boost/test/results_collector.hpp:40:13: warning: unused function 'first_failed_assertion' [-Wunused-function]
  //(void)first_failed_assertion;

  //../../../boost/test/tools/floating_point_comparison.hpp:304:25: warning: unused variable 'check_is_close' [-Wunused-variable]
  //../../../boost/test/tools/floating_point_comparison.hpp:326:25: warning: unused variable 'check_is_small' [-Wunused-variable]
  (void)boost::test_tools::check_is_close;
  (void)boost::test_tools::check_is_small;

}
