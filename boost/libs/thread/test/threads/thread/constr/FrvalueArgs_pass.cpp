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

// <boost/thread/thread.hpp>

// class thread

// template <class F, class ...Args> thread(F&& f, Args&&... args);

#include <boost/thread/thread.hpp>
#include <new>
#include <cstdlib>
#include <cassert>
#include <boost/detail/lightweight_test.hpp>

class MoveOnly
{
  BOOST_THREAD_MOVABLE_ONLY(MoveOnly)
  MoveOnly()
  {
  }
  MoveOnly(BOOST_THREAD_RV_REF(MoveOnly))
  {}

  void operator()(BOOST_THREAD_RV_REF(MoveOnly))
  {
  }
};

int main()
{
  {
    boost::thread t = boost::thread( BOOST_THREAD_MAKE_RV_REF(MoveOnly()), BOOST_THREAD_MAKE_RV_REF(MoveOnly()) );
    t.join();
  }
  return boost::report_errors();
}
