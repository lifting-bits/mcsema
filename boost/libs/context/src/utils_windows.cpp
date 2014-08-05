
//          Copyright Oliver Kowalke 2009.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#define BOOST_CONTEXT_SOURCE

#include <boost/context/guarded_stack_allocator.hpp>

extern "C" {
#include <windows.h>
}

#include <boost/config.hpp>

#ifdef BOOST_HAS_ABI_HEADERS
#  include BOOST_ABI_PREFIX
#endif

namespace {

static SYSTEM_INFO system_info_()
{
    SYSTEM_INFO si;
    ::GetSystemInfo( & si);
    return si;
}

static SYSTEM_INFO system_info()
{
    static SYSTEM_INFO si = system_info_();
    return si;
}

}

namespace boost {
namespace context {

std::size_t pagesize()
{ return static_cast< std::size_t >( system_info().dwPageSize); }

}}

#ifdef BOOST_HAS_ABI_HEADERS
#  include BOOST_ABI_SUFFIX
#endif
