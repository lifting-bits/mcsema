
//          Copyright Oliver Kowalke 2009.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

#include <boost/assert.hpp>
#include <boost/context/all.hpp>

namespace ctx = boost::context;

ctx::fcontext_t * fc1;
ctx::fcontext_t * fc2;

void f1( intptr_t)
{
        std::cout << "f1: entered" << std::endl;
        std::cout << "f1: call jump_fcontext( fc1, fc2, 0)" << std::endl;
        ctx::jump_fcontext( fc1, fc2, 0);
        std::cout << "f1: return" << std::endl;
}

void f2( intptr_t)
{
        std::cout << "f2: entered" << std::endl;
        std::cout << "f2: call jump_fcontext( fc2, fc1, 0)" << std::endl;
        ctx::jump_fcontext( fc2, fc1, 0);
        BOOST_ASSERT( false && ! "f2: never returns");
}

int main( int argc, char * argv[])
{
        ctx::fcontext_t fcm;
        ctx::guarded_stack_allocator alloc;

        void * sp1 = alloc.allocate(ctx::guarded_stack_allocator::default_stacksize());
        fc1 = ctx::make_fcontext( sp1, ctx::guarded_stack_allocator::default_stacksize(), f1);

        void * sp2 = alloc.allocate(ctx::guarded_stack_allocator::default_stacksize());
        fc2 = ctx::make_fcontext( sp2, ctx::guarded_stack_allocator::default_stacksize(), f2);

        std::cout << "main: call start_fcontext( & fcm, fc1, 0)" << std::endl;
        ctx::jump_fcontext( & fcm, fc1, 0);

        std::cout << "main: done" << std::endl;
        BOOST_ASSERT( false && ! "main: never returns");

        return EXIT_SUCCESS;
}
