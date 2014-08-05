
//          Copyright Oliver Kowalke 2009.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#define BOOST_CONTEXT_SOURCE

#include <boost/context/guarded_stack_allocator.hpp>

extern "C" {
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
}

//#if _POSIX_C_SOURCE >= 200112L

#include <algorithm>
#include <cmath>
#include <cstring>
#include <stdexcept>

#include <boost/assert.hpp>
#include <boost/config.hpp>

#include <boost/context/fcontext.hpp>
#include <boost/context/utils.hpp>

#if !defined (SIGSTKSZ)
# define SIGSTKSZ (8 * 1024)
#endif

#ifdef BOOST_HAS_ABI_HEADERS
#  include BOOST_ABI_PREFIX
#endif

namespace {

static rlimit stacksize_limit_()
{
    rlimit limit;
    // conforming to POSIX.1-2001
    const int result = ::getrlimit( RLIMIT_STACK, & limit);
    BOOST_ASSERT( 0 == result);
    return limit;
}

static rlimit stacksize_limit()
{
    static rlimit limit = stacksize_limit_();
    return limit;
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

bool
guarded_stack_allocator::is_stack_unbound()
{ return RLIM_INFINITY == stacksize_limit().rlim_max; }

std::size_t
guarded_stack_allocator::maximum_stacksize()
{
    BOOST_ASSERT( ! is_stack_unbound() );
    return static_cast< std::size_t >( stacksize_limit().rlim_max);
}

std::size_t
guarded_stack_allocator::minimum_stacksize()
{ return SIGSTKSZ + sizeof( fcontext_t) + 15; }

std::size_t
guarded_stack_allocator::default_stacksize()
{
    std::size_t size = 8 * minimum_stacksize();
    if ( is_stack_unbound() ) return size;
    
    BOOST_ASSERT( maximum_stacksize() >= minimum_stacksize() );
    return maximum_stacksize() == size
        ? size
        : std::min( size, maximum_stacksize() );
}

void *
guarded_stack_allocator::allocate( std::size_t size) const
{
    BOOST_ASSERT( minimum_stacksize() <= size);
    BOOST_ASSERT( is_stack_unbound() || ( maximum_stacksize() >= size) );

    const std::size_t pages( page_count( size) + 1); // add one guard page
    const std::size_t size_( pages * pagesize() );
    BOOST_ASSERT( 0 < size && 0 < size_);

    const int fd( ::open("/dev/zero", O_RDONLY) );
    BOOST_ASSERT( -1 != fd);
    // conform to POSIX.4 (POSIX.1b-1993, _POSIX_C_SOURCE=199309L)
    void * limit =
# if defined(macintosh) || defined(__APPLE__) || defined(__APPLE_CC__)
        ::mmap( 0, size_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
# else
        ::mmap( 0, size_, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
# endif
    ::close( fd);
    if ( ! limit) throw std::bad_alloc();

    std::memset( limit, size_, '\0');

    // conforming to POSIX.1-2001
    const int result( ::mprotect( limit, pagesize(), PROT_NONE) );
    BOOST_ASSERT( 0 == result);

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
    // conform to POSIX.4 (POSIX.1b-1993, _POSIX_C_SOURCE=199309L)
    ::munmap( limit, size_);
}

}}

#ifdef BOOST_HAS_ABI_HEADERS
#  include BOOST_ABI_SUFFIX
#endif

//#endif
