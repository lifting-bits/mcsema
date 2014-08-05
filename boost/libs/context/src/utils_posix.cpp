
//          Copyright Oliver Kowalke 2009.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#define BOOST_CONTEXT_SOURCE

#include <boost/context/guarded_stack_allocator.hpp>

extern "C" {
#include <unistd.h>
}

//#if _POSIX_C_SOURCE >= 200112L

#include <boost/config.hpp>

#ifdef BOOST_HAS_ABI_HEADERS
#  include BOOST_ABI_PREFIX
#endif

namespace boost {
namespace context {

std::size_t pagesize()
{
    // conform to POSIX.1-2001
    static std::size_t size = ::sysconf( _SC_PAGESIZE);
    return size;
}

}}

#ifdef BOOST_HAS_ABI_HEADERS
#  include BOOST_ABI_SUFFIX
#endif

//#endif
