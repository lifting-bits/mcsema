
// Copyright 2005-2009 Daniel James.
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include "./config.hpp"

#ifdef TEST_EXTENSIONS
#  ifdef TEST_STD_INCLUDES
#    include <functional>
#  else
#    include <boost/functional/hash.hpp>
#  endif
#endif

#include <boost/detail/lightweight_test.hpp>

#ifdef TEST_EXTENSIONS

#include <list>

using std::list;
#define CONTAINER_TYPE list
#include "./hash_sequence_test.hpp"

#endif // TEST_EXTENSIONS

int main()
{
#ifdef TEST_EXTENSIONS
    list_tests::list_hash_integer_tests();
#endif

    return boost::report_errors();
}
