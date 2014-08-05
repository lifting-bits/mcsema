
// Copyright 2005-2009 Daniel James.
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#if defined(TEST_STD)
#  define TEST_STD_INCLUDES
#  define HASH_NAMESPACE std
#else
#  define HASH_NAMESPACE boost
#  if !defined(BOOST_HASH_NO_EXTENSIONS)
#    define TEST_EXTENSIONS
#  endif
#endif

#if defined(_WIN32_WCE)
// The standard windows mobile headers trigger this warning so I disable it
// before doing anything else.
#pragma warning(disable:4201)   // nonstandard extension used :
                                // nameless struct/union
#endif
