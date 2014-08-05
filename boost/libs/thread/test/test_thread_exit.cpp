//  (C) Copyright 2009 Anthony Williams
//
//  Distributed under the Boost Software License, Version 1.0. (See
//  accompanying file LICENSE_1_0.txt or copy at
//  http://www.boost.org/LICENSE_1_0.txt)

#include <boost/thread/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/condition.hpp>
#include <boost/thread/future.hpp>
#include <utility>
#include <memory>
#include <string>

#include <boost/test/unit_test.hpp>

boost::thread::id exit_func_thread_id;

void exit_func()
{
    exit_func_thread_id=boost::this_thread::get_id();
}

void tf1()
{
    boost::this_thread::at_thread_exit(exit_func);
    BOOST_CHECK(exit_func_thread_id!=boost::this_thread::get_id());
}

void test_thread_exit_func_runs_when_thread_exits()
{
    exit_func_thread_id=boost::thread::id();
    boost::thread t(tf1);
    boost::thread::id const t_id=t.get_id();
    t.join();
    BOOST_CHECK(exit_func_thread_id==t_id);
}

struct fo
{
    void operator()()
    {
        exit_func_thread_id=boost::this_thread::get_id();
    }
};

void tf2()
{
    boost::this_thread::at_thread_exit(fo());
    BOOST_CHECK(exit_func_thread_id!=boost::this_thread::get_id());
}


void test_can_use_function_object_for_exit_func()
{
    exit_func_thread_id=boost::thread::id();
    boost::thread t(tf2);
    boost::thread::id const t_id=t.get_id();
    t.join();
    BOOST_CHECK(exit_func_thread_id==t_id);
}


boost::unit_test::test_suite* init_unit_test_suite(int, char*[])
{
    boost::unit_test::test_suite* test =
        BOOST_TEST_SUITE("Boost.Threads: futures test suite");

    test->add(BOOST_TEST_CASE(test_thread_exit_func_runs_when_thread_exits));
    test->add(BOOST_TEST_CASE(test_can_use_function_object_for_exit_func));

    return test;
}

void remove_unused_warning()
{

  //../../../boost/test/results_collector.hpp:40:13: warning: unused function 'first_failed_assertion' [-Wunused-function]
  //(void)boost::unit_test::first_failed_assertion;

  //../../../boost/test/tools/floating_point_comparison.hpp:304:25: warning: unused variable 'check_is_close' [-Wunused-variable]
  //../../../boost/test/tools/floating_point_comparison.hpp:326:25: warning: unused variable 'check_is_small' [-Wunused-variable]
  (void)boost::test_tools::check_is_close;
  (void)boost::test_tools::check_is_small;

}
