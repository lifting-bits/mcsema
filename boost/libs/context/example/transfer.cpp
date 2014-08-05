
//          Copyright Oliver Kowalke 2009.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <utility>
#include <vector>

#include <boost/assert.hpp>
#include <boost/context/all.hpp>

namespace ctx = boost::context;

ctx::fcontext_t fcm;
ctx::fcontext_t * fc1;

typedef std::pair< int, int >   pair_t;

void f1( intptr_t param)
{
    pair_t * p = ( pair_t *) param;

    p = ( pair_t *) ctx::jump_fcontext( fc1, & fcm, ( intptr_t) ( p->first + p->second) );

    ctx::jump_fcontext( fc1, & fcm, ( intptr_t) ( p->first + p->second) );
}

int main( int argc, char * argv[])
{
    typedef ctx::simple_stack_allocator< 256 * 1024, 64 * 1024, 8 * 1024 > alloc_t;
    alloc_t alloc;

    void * sp = alloc.allocate(alloc_t::default_stacksize());
    fc1 = ctx::make_fcontext( sp, alloc_t::default_stacksize(), f1);

    pair_t p( std::make_pair( 2, 7) );
    int res = ( int) ctx::jump_fcontext( & fcm, fc1, ( intptr_t) & p);
    std::cout << p.first << " + " << p.second << " == " << res << std::endl;

    p = std::make_pair( 5, 6);
    res = ( int) ctx::jump_fcontext( & fcm, fc1, ( intptr_t) & p);
    std::cout << p.first << " + " << p.second << " == " << res << std::endl;

    std::cout << "main: done" << std::endl;

    return EXIT_SUCCESS;
}
