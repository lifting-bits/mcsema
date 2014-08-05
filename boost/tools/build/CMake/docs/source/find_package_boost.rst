..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

.. index:: find_package(Boost)
.. index:: FindBoost.cmake

.. _find_package_boost:

find_package(Boost)
===================

See :ref:`install_customization` for more information about variables
used in this section.

If you plan on using the ``FindBoost.cmake`` packaged with cmake
versions 2.8.0 and earlier, (that is, third party packages that build
with cmake need to find this boost installation via the cmake command
``find_package(Boost...``), you will need to layout your boost
installation in a way that is consistent with the way boost was
installed by bjam during the many Dark Years.  Michael Jackson of
bluequartz.net reports success with the configuration below.  He
refers to boost.cmake variables :ref:`install_versioned`,
:ref:`boost_include_install_dir`, and :ref:`boost_lib_install_dir`::

  > Set INSTALL_VERSIONED=OFF
  > set BOOST_INCLUDE_INSTALL_DIR=include/boost-1_41
  > set BOOST_LIB_INSTALL_DIR=lib
  > 
  > and then go. I also set an environment variable BOOST_ROOT to the 
  > CMAKE_INSTALL_PREFIX.
  > 
  > In my CMake file I have the following;
  > 
  > # ---------- Find Boost Headers/Libraries -----------------------
  > SET (Boost_FIND_REQUIRED TRUE)
  > SET (Boost_FIND_QUIETLY TRUE)
  > set (Boost_USE_MULTITHREADED TRUE)
  > set (Boost_USE_STATIC_LIBS TRUE)
  > SET (Boost_ADDITIONAL_VERSIONS "1.41" "1.41.0")
  > 
  > if ( NOT MXA_BOOST_HEADERS_ONLY)
  >  set (MXA_BOOST_COMPONENTS program_options unit_test_framework 
  > test_exec_monitor)
  > endif()
  > FIND_PACKAGE(Boost COMPONENTS  ${MXA_BOOST_COMPONENTS} )
  > INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})
  > LINK_DIRECTORIES(${Boost_LIBRARY_DIRS})
  > 
  > This successfully works with the FindBoost.cmake that is included with CMake 2.6.4
  > 

Currently in development there are other, perhaps easier, ways to
detect your boost installations if you aren't dependent on this older
FindBoost; see :ref:`exported_targets`.

