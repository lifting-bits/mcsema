/* Boost.MultiIndex test for standard hash operations.
 *
 * Copyright 2003-2008 Joaquin M Lopez Munoz.
 * Distributed under the Boost Software License, Version 1.0.
 * (See accompanying file LICENSE_1_0.txt or copy at
 * http://www.boost.org/LICENSE_1_0.txt)
 *
 * See http://www.boost.org/libs/multi_index for library home page.
 */

#include <boost/test/included/test_exec_monitor.hpp>
#include "test_hash_ops.hpp"

int test_main(int,char *[])
{
  test_hash_ops();
  return 0;
}
