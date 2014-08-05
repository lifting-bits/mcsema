..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

boost_additional_test_dependencies
----------------------------------

.. note:: This is only needed in the presence of 'modularization'
   	  which is currently disabled.

Add additional include directories based on the dependencies of the
library being tested 'libname' and all of its dependencies.

.. cmake:: boost_additional_test_dependencies(libname, ...

   :param libname: name of library being tested
   :param BOOST_DEPENDS: libdepend1 libdepend2 ...

`libname` 

   the name of the boost library being tested. (signals)

`BOOST_DEPENDS`

   The list of the extra boost libraries that the test suite will
   depend on. You do NOT have to list those libraries already listed
   by the module.cmake file as these will be used.

.. rubric:: Example

The following invocation of the `boost_additional_test_dependencies`
macro is taken from the signals library. ::

  boost_additional_test_dependencies(signals BOOST_DEPENDS test optional)

.. rubric:: Where Defined

This macro is defined in the Boost Testing module in
tools/build/CMake/BoostTesting.cmake

