// Copyright (C) 2009 Anthony Williams
//
//  Distributed under the Boost Software License, Version 1.0. (See accompanying
//  file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#define BOOST_THREAD_USES_MOVE

#include <boost/thread/thread.hpp>
#include <boost/test/unit_test.hpp>

void do_nothing(boost::thread::id* my_id)
{
    *my_id=boost::this_thread::get_id();
}

boost::thread make_thread_return_local(boost::thread::id* the_id)
{
    boost::thread t(do_nothing,the_id);
    return boost::move(t);
}

void test_move_from_function_return_local()
{
    boost::thread::id the_id;
    boost::thread x=make_thread_return_local(&the_id);
    boost::thread::id x_id=x.get_id();
    x.join();
    BOOST_CHECK_EQUAL(the_id,x_id);
}

boost::unit_test::test_suite* init_unit_test_suite(int, char*[])
{
    boost::unit_test::test_suite* test =
        BOOST_TEST_SUITE("Boost.Threads: thread move test suite");

    test->add(BOOST_TEST_CASE(test_move_from_function_return_local));
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
