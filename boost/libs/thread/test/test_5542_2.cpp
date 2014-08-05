// Copyright (C) 2010 Vicente Botet
//
//  Distributed under the Boost Software License, Version 1.0. (See accompanying
//  file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <boost/thread.hpp>

void run_thread() {
        return;
}

int main() {
        boost::thread t(run_thread);
        return 0;
}

