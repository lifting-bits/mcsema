
//          Copyright Oliver Kowalke 2009.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#define BOOST_CONTEXT_SOURCE
#define NOMINMAX

#include <boost/context/guarded_stack_allocator.hpp>

extern "C" {
#include <windows.h>
}

#include <algorithm>
#include <cmath>
#include <csignal>
#include <cstring>
#include <stdexcept>

#include <boost/assert.hpp>
#include <boost/config.hpp>
#include <boost/cstdint.hpp>

#include <boost/context/utils.hpp>

# if defined(BOOST_MSVC)
# pragma warning(push)
# pragma warning(disable:4244 4267)
# endif

// x86_64
// test x86_64 before i386 because icc might
// define __i686__ for x86_64 too
#if defined(__x86_64__) || defined(__x86_64) \
    || defined(__amd64__) || defined(__amd64) \
    || defined(_M_X64) || defined(_M_AMD64)

// Windows seams not to provide a constant or function
// telling the minimal stacksize
# define MIN_STACKSIZE  8 * 1024
#else
# define MIN_STACKSIZE  4 * 1024
#endif

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

static std::size_t page_count( std::size_t stacksize)
{
    return static_cast< std::size_t >(
        std::ceil(
            static_cast< float >( stacksize) / boost::context::pagesize() ) );
}

}

namespace boost {
namespace context {

// Windows seams not to provide a limit for the stacksize
bool
guarded_stack_allocator::is_stack_unbound()
{ return true; }

// because Windows seams not to provide a limit for maximum stacksize
// maximum_stacksize() can never be called (pre-condition ! is_stack_unbound() )
std::size_t
guarded_stack_allocator::maximum_stacksize()
{
    BOOST_ASSERT( ! is_stack_unbound() );
    return  1 * 1024 * 1024 * 1024; // 1GB
}

// because Windows seams not to provide a limit for minimum stacksize
std::size_t
guarded_stack_allocator::minimum_stacksize()
{ return MIN_STACKSIZE; }

std::size_t
guarded_stack_allocator::default_stacksize()
{
    std::size_t size = 64 * 1024; // 64 kB
    if ( is_stack_unbound() )
        return std::max( size, minimum_stacksize() );
    
    BOOST_ASSERT( maximum_stacksize() >= minimum_stacksize() );
    return maximum_stacksize() == minimum_stacksize()
        ? minimum_stacksize()
        : std::min( size, maximum_stacksize() );
}

void *
guarded_stack_allocator::allocate( std::size_t size) const
{
    BOOST_ASSERT( minimum_stacksize() <= size);
    BOOST_ASSERT( is_stack_unbound() || ( maximum_stacksize() >= size) );

    const std::size_t pages( page_count( size) + 1); // add one guard page
    const std::size_t size_ = pages * pagesize();
    BOOST_ASSERT( 0 < size && 0 < size_);

    void * limit = ::VirtualAlloc( 0, size_, MEM_COMMIT, PAGE_READWRITE);
    if ( ! limit) throw std::bad_alloc();

    std::memset( limit, size_, '\0');

    DWORD old_options;
    const BOOL result = ::VirtualProtect(
        limit, pagesize(), PAGE_READWRITE | PAGE_GUARD /*PAGE_NOACCESS*/, & old_options);
    BOOST_ASSERT( FALSE != result);

    return static_cast< char * >( limit) + size_;
}

void
guarded_stack_allocator::deallocate( void * vp, std::size_t size) const
{
    BOOST_ASSERT( vp);
    BOOST_ASSERT( minimum_stacksize() <= size);
    BOOST_ASSERT( is_stack_unbound() || ( maximum_stacksize() >= size) );

    const std::size_t pages = page_count( size) + 1;
    const std::size_t size_ = pages * pagesize();
    BOOST_ASSERT( 0 < size && 0 < size_);
    void * limit = static_cast< char * >( vp) - size_;
    ::VirtualFree( limit, 0, MEM_RELEASE);
}

}}

#ifdef BOOST_HAS_ABI_HEADERS
#  include BOOST_ABI_SUFFIX
#endif

# if defined(BOOST_MSVC)
# pragma warning(pop)
# endif
