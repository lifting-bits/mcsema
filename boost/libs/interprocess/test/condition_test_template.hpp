// Copyright (C) 2001-2003
// William E. Kempf
//
// Permission to use, copy, modify, distribute and sell this software
// and its documentation for any purpose is hereby granted without fee,
// provided that the above copyright notice appear in all copies and
// that both that copyright notice and this permission notice appear
// in supporting documentation.  William E. Kempf makes no representations
// about the suitability of this software for any purpose.
// It is provided "as is" without express or implied warranty.
//////////////////////////////////////////////////////////////////////////////
//
// (C) Copyright Ion Gaztanaga 2005-2012. Distributed under the Boost
// Software License, Version 1.0. (See accompanying file
// LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// See http://www.boost.org/libs/interprocess for documentation.
//
//////////////////////////////////////////////////////////////////////////////
#ifndef BOOST_INTERPROCESS_CONDITION_TEST_TEMPLATE_HPP
#define BOOST_INTERPROCESS_CONDITION_TEST_TEMPLATE_HPP

#include <boost/interprocess/detail/config_begin.hpp>
#include <boost/interprocess/detail/workaround.hpp>
#include "boost_interprocess_check.hpp"
#include <boost/thread/detail/config.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>
#include <boost/thread/thread.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/thread/xtime.hpp>
#include <boost/version.hpp>
#include <iostream>

namespace boost{
namespace interprocess{
namespace test {

boost::posix_time::ptime ptime_delay(int secs)
{
   return   microsec_clock::universal_time() +
            boost::posix_time::time_duration(0, 0, secs);
}

inline boost::xtime delay(int secs, int msecs=0, int nsecs=0)
{
    const int MILLISECONDS_PER_SECOND = 1000;
    const int NANOSECONDS_PER_SECOND = 1000000000;
    const int NANOSECONDS_PER_MILLISECOND = 1000000;

    boost::xtime xt;

    #if BOOST_VERSION >= 105100 //TIME_UTC is a macro in C11, breaking change in Boost.Thread
    int ret = boost::xtime_get(&xt, boost::TIME_UTC_);
    BOOST_INTERPROCES_CHECK(ret == static_cast<int>(boost::TIME_UTC_));(void)ret;
    #else
    int ret = boost::xtime_get(&xt, boost::TIME_UTC);
    BOOST_INTERPROCES_CHECK(ret == static_cast<int>(boost::TIME_UTC));(void)ret;
    #endif
    nsecs += xt.nsec;
    msecs += nsecs / NANOSECONDS_PER_MILLISECOND;
    secs += msecs / MILLISECONDS_PER_SECOND;
    nsecs += (msecs % MILLISECONDS_PER_SECOND) * NANOSECONDS_PER_MILLISECOND;
    xt.nsec = nsecs % NANOSECONDS_PER_SECOND;
    xt.sec += secs + (nsecs / NANOSECONDS_PER_SECOND);

    return xt;
}

template <typename F, typename T>
class binder
{
public:
    binder(const F& func, const T& param)
        : func(func), param(param) { }
    void operator()() const { func(param); }

private:
    F func;
    T param;
};

template <typename F, typename T>
binder<F, T> bind_function(F func, T param)
{
    return binder<F, T>(func, param);
}

template <class Condition, class Mutex>
struct condition_test_data
{
   condition_test_data() : notified(0), awoken(0) { }

   ~condition_test_data()
   {}

   Mutex      mutex;
   Condition  condition;
   int notified;
   int awoken;
};

template <class Condition, class Mutex>
void condition_test_thread(condition_test_data<Condition, Mutex>* data)
{
    boost::interprocess::scoped_lock<Mutex>
      lock(data->mutex);
    BOOST_INTERPROCES_CHECK(lock ? true : false);
    while (!(data->notified > 0))
        data->condition.wait(lock);
    BOOST_INTERPROCES_CHECK(lock ? true : false);
    data->awoken++;
}

struct cond_predicate
{
    cond_predicate(int& var, int val) : _var(var), _val(val) { }

    bool operator()() { return _var == _val; }

    int& _var;
    int _val;
};

template <class Condition, class Mutex>
void condition_test_waits(condition_test_data<Condition, Mutex>* data)
{
    boost::interprocess::scoped_lock<Mutex>
      lock(data->mutex);
    BOOST_INTERPROCES_CHECK(lock ? true : false);

    // Test wait.
    while (data->notified != 1)
        data->condition.wait(lock);
    BOOST_INTERPROCES_CHECK(lock ? true : false);
    BOOST_INTERPROCES_CHECK(data->notified == 1);
    data->awoken++;
    data->condition.notify_one();

    // Test predicate wait.
    data->condition.wait(lock, cond_predicate(data->notified, 2));
    BOOST_INTERPROCES_CHECK(lock ? true : false);
    BOOST_INTERPROCES_CHECK(data->notified == 2);
    data->awoken++;
    data->condition.notify_one();

    // Test timed_wait.
    while (data->notified != 3)
        data->condition.timed_wait(lock, ptime_delay(5));
    BOOST_INTERPROCES_CHECK(lock ? true : false);
    BOOST_INTERPROCES_CHECK(data->notified == 3);
    data->awoken++;
    data->condition.notify_one();

    // Test predicate timed_wait.
    cond_predicate pred(data->notified, 4);
    bool ret = data->condition.timed_wait(lock, ptime_delay(5), pred);
    BOOST_INTERPROCES_CHECK(ret);(void)ret;
    BOOST_INTERPROCES_CHECK(lock ? true : false);
    BOOST_INTERPROCES_CHECK(pred());
    BOOST_INTERPROCES_CHECK(data->notified == 4);
    data->awoken++;
    data->condition.notify_one();
}

template <class Condition, class Mutex>
void do_test_condition_notify_one()
{
   condition_test_data<Condition, Mutex> data;

   boost::thread thread(bind_function(&condition_test_thread<Condition, Mutex>, &data));
   //Make sure thread is blocked
   boost::thread::sleep(delay(1));
   {
      boost::interprocess::scoped_lock<Mutex>
         lock(data.mutex);
      BOOST_INTERPROCES_CHECK(lock ? true : false);
      data.notified++;
      data.condition.notify_one();
   }

   thread.join();
   BOOST_INTERPROCES_CHECK(data.awoken == 1);
}

template <class Condition, class Mutex>
void do_test_condition_notify_all()
{
   const int NUMTHREADS = 3;
   boost::thread_group threads;
   condition_test_data<Condition, Mutex> data;

   for (int i = 0; i < NUMTHREADS; ++i){
       threads.create_thread(bind_function(&condition_test_thread<Condition, Mutex>, &data));
   }
   //Make sure all threads are blocked
   boost::thread::sleep(delay(1));
   {
      boost::interprocess::scoped_lock<Mutex>
         lock(data.mutex);
      BOOST_INTERPROCES_CHECK(lock ? true : false);
      data.notified++;
   }
   data.condition.notify_all();

   threads.join_all();
   BOOST_INTERPROCES_CHECK(data.awoken == NUMTHREADS);
}

template <class Condition, class Mutex>
void do_test_condition_waits()
{
   condition_test_data<Condition, Mutex> data;

   boost::thread thread(bind_function(&condition_test_waits<Condition, Mutex>, &data));

   {
      boost::interprocess::scoped_lock<Mutex>
         lock(data.mutex);
      BOOST_INTERPROCES_CHECK(lock ? true : false);

      boost::thread::sleep(delay(1));
      data.notified++;
      data.condition.notify_one();
      while (data.awoken != 1)
         data.condition.wait(lock);
      BOOST_INTERPROCES_CHECK(lock ? true : false);
      BOOST_INTERPROCES_CHECK(data.awoken == 1);

      boost::thread::sleep(delay(1));
      data.notified++;
      data.condition.notify_one();
      while (data.awoken != 2)
         data.condition.wait(lock);
      BOOST_INTERPROCES_CHECK(lock ? true : false);
      BOOST_INTERPROCES_CHECK(data.awoken == 2);

      boost::thread::sleep(delay(1));
      data.notified++;
      data.condition.notify_one();
      while (data.awoken != 3)
         data.condition.wait(lock);
      BOOST_INTERPROCES_CHECK(lock ? true : false);
      BOOST_INTERPROCES_CHECK(data.awoken == 3);

      boost::thread::sleep(delay(1));
      data.notified++;
      data.condition.notify_one();
      while (data.awoken != 4)
         data.condition.wait(lock);
      BOOST_INTERPROCES_CHECK(lock ? true : false);
      BOOST_INTERPROCES_CHECK(data.awoken == 4);
   }

   thread.join();
   BOOST_INTERPROCES_CHECK(data.awoken == 4);
}
/*
//Message queue simulation test
template <class Condition>
inline Condition &cond_empty()
{
   static Condition cond_empty;
   return cond_empty;
}

template <class Condition>
inline Condition &cond_full()
{
   static Condition cond_full;
   return cond_full;
}


template <class Mutex>
inline Mutex &mutex()
{
   static Mutex mut;
   return mut;
}
*/
static volatile int count = 0;
static volatile int waiting_readers = 0;
static volatile int waiting_writer  = 0;
const int queue_size    = 3;
const int thread_factor = 10;
const int NumThreads    = thread_factor*queue_size;

//Function that removes items from queue
template <class Condition, class Mutex>
struct condition_func
{
   condition_func(Condition &cond_full, Condition &cond_empty, Mutex &mutex)
      :  cond_full_(cond_full), cond_empty_(cond_empty), mutex_(mutex)
   {}

   void operator()()
   {
      boost::interprocess::scoped_lock<Mutex>lock(mutex_);
      while(count == 0){
         ++waiting_readers;
         cond_empty_.wait(lock);
         --waiting_readers;
      }
      --count;
      if(waiting_writer)
         cond_full_.notify_one();
   }
   Condition &cond_full_;
   Condition &cond_empty_;
   Mutex     &mutex_;
};

//Queue functions
template <class Condition, class Mutex>
void do_test_condition_queue_notify_one(void)
{
   //Force mutex and condition creation
   Condition cond_empty;
   Condition cond_full;
   Mutex mutex;

   //Create threads that will decrease count
   {
      //Initialize counters
      count = 0;
      waiting_readers = 0;
      waiting_writer  = 0;

      boost::thread_group thgroup;
      int i;
      for(i = 0; i< NumThreads; ++i){
         condition_func<Condition, Mutex> func(cond_full, cond_empty, mutex);
         thgroup.create_thread(func);
      }

      //Add 20 elements one by one in the queue simulation
      //The sender will block if it fills the queue
      for(i = 0; i < NumThreads; ++i){
         boost::interprocess::scoped_lock<Mutex> lock(mutex);
         while(count == queue_size){
            ++waiting_writer;
            cond_full.wait(lock);
            --waiting_writer;
         }
         count++;

         if(waiting_readers)
            cond_empty.notify_one();
      }
      thgroup.join_all();
      BOOST_INTERPROCES_CHECK(count == 0);
      BOOST_INTERPROCES_CHECK(waiting_readers == 0);
      BOOST_INTERPROCES_CHECK(waiting_writer  == 0);
   }
}

//Queue functions
template <class Condition, class Mutex>
void do_test_condition_queue_notify_all(void)
{
   //Force mutex and condition creation
   Condition cond_empty;
   Condition cond_full;
   Mutex mutex;

   //Create threads that will decrease count
   {
      //Initialize counters
      count = 0;
      waiting_readers = 0;
      waiting_writer  = 0;

      boost::thread_group thgroup;
      int i;
      for(i = 0; i< NumThreads; ++i){
         condition_func<Condition, Mutex> func(cond_full, cond_empty, mutex);
         thgroup.create_thread(func);
      }

      //Fill queue to the max size and notify all several times
      for(i = 0; i < NumThreads; ++i){
         boost::interprocess::scoped_lock<Mutex>lock(mutex);
         while(count == queue_size){
            ++waiting_writer;
            cond_full.wait(lock);
            --waiting_writer;
         }
         count++;

         if(waiting_readers)
            cond_empty.notify_all();
      }
      thgroup.join_all();
      BOOST_INTERPROCES_CHECK(count == 0);
      BOOST_INTERPROCES_CHECK(waiting_readers == 0);
      BOOST_INTERPROCES_CHECK(waiting_writer  == 0);
   }
}

template <class Condition, class Mutex>
bool do_test_condition()
{
   std::cout << "do_test_condition_notify_one<" << typeid(Condition).name() << "," << typeid(Mutex).name() << '\n' << std::endl;
   do_test_condition_notify_one<Condition, Mutex>();
   std::cout << "do_test_condition_notify_all<" << typeid(Condition).name() << "," << typeid(Mutex).name() << '\n' << std::endl;
   do_test_condition_notify_all<Condition, Mutex>();
   std::cout << "do_test_condition_waits<" << typeid(Condition).name() << "," << typeid(Mutex).name() << '\n' << std::endl;
   do_test_condition_waits<Condition, Mutex>();
   std::cout << "do_test_condition_queue_notify_one<" << typeid(Condition).name() << "," << typeid(Mutex).name() << '\n' << std::endl;
   do_test_condition_queue_notify_one<Condition, Mutex>();
   std::cout << "do_test_condition_queue_notify_all<" << typeid(Condition).name() << "," << typeid(Mutex).name() << '\n' << std::endl;
   do_test_condition_queue_notify_all<Condition, Mutex>();
   return true;
}

}  //namespace test
}  //namespace interprocess{
}  //namespace boost{

#include <boost/interprocess/detail/config_end.hpp>

#endif   //#ifndef BOOST_INTERPROCESS_CONDITION_TEST_TEMPLATE_HPP
