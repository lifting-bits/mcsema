// Copyright (C) 2001-2003
// William E. Kempf
//
//  Distributed under the Boost Software License, Version 1.0. (See accompanying
//  file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <boost/thread/thread.hpp>
#include <iostream>

int count = 0;
boost::mutex mutex;

void increment_count()
{
    boost::mutex::scoped_lock lock(mutex);
    std::cout << "count = " << ++count << std::endl;
}

int main()
{
    boost::thread_group threads;
    for (int i = 0; i < 10; ++i)
        threads.create_thread(&increment_count);
    threads.join_all();
}
