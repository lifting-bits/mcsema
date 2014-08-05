..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

Notes by Boost Version
======================

1.41.0.cmake1
-------------------

Again, innumerable tiny tweaks.   

1.41.0.beta1.cmake1
-------------------

This is the first cmake beta based on upstream ``Boost_1_41_0_beta1``.
There are *way* too many enhancements to mention.

1.41.0.cmakebeta4
-----------------

* CMake minimum 2.6.4 required (found bugs with 2.6.2)
* Move MPI detection up 
* Clean up output

1.41.0.cmakebeta3
-----------------

* :ref:`variants` names switched to ``ENABLE_<feature>`` to distinguish 
  from ``BUILD_*`` options.

* Many docs improvements

* Special targets for the boost-cmake maintainer

* :ref:`BUILD_PROJECTS` ``(= NONE|ALL|proj1;proj2;...;projN)``
  variable for building only certain projects.

* :ref:`BUILD_EXAMPLES` ``(= NONE|ALL|proj1;proj2;...;projN)``
  variable for building examples only of certain projects.

* :ref:`LIB_SUFFIX` for installing libs to nonstandard lib directory
  name, e.g. for LIB_SUFFIX=64, libs installed to ``$PREFIX/lib64``

* Testing improvements: cmake now runs 2408 tests, 99% of which pass.
  This isn't the full set, upstream is a moving target.  The few
  remaining failures (assuming upstream is bug-free) are assumed to be
  problems in the testing setup, not the underlying libraries.

* Python: python location customizable via command line or environment
  variables, see :ref:`external_dependencies`.
  
(1.41.0.cmakebeta1 and 2 omitted)

1.41.0 (upstream)
-----------------

This release (as released by upstream Boost) does **not** contain
CMake support.  See above for independenly released CMake versions.

1.40.0.cmake4
-------------

Backport features from 1.41.0.cmakebeta3

1.40.0.cmake3
-------------

Skipped

1.40.0.cmake2
-------------

* Modularization disabled... this can waste your source directory
  and was causing confusion.
* Docs tagged with specific boost-cmake release version.

1.40.0.cmake1
-------------

From the boost-cmake list::

  > As of now, your Boost 1.40.0 branch builds and installs without error 
  > for me on Windows (Intel 11.1, Visual Studio 2009, Visual Studio 2010 
  > Beta 1), Linux (GCC 4.2, GCC 4.4, Intel 11.1), and Mac OS X 10.6 (GCC 
  > 4.2, Intel 11.1).

This version also includes fixes for cmake version 2.8 (as of this
writing, in beta).

Special thanks in alphabetical order:

* Claudio Bley
* Justin Holewinski
* Philip Lowman

1.40.0.cmake0
-------------

This version works on windows with MSVC and linux with gcc.

1.40.0
------

This version is **broken** in the svn distribution.  See later
releases with the ``.cmakeN`` suffix.

1.38.0 and 1.39.0
-----------------

.. warning:: -DCMAKE_IS_EXPERIMENTAL=ORLY_YARLY

   This guard variable is included in releases of Boost.CMake through
   version 1.38.  You just need to set this variable to some value (be
   creative) when running cmake for the first time to disable the
   guard.

Boost.CMake was included as an experimental system for the first time.
It is perfectly capable of doing the basic build and install of boost.
You *must* pass the argument ::

  -DCMAKE_IS_EXPERIMENTAL=ORLY

to the initial run of cmake, or you will see an intimidating message
explaining that Boost.CMake != Boost.Build.  It looks like this::

  -- ##########################################################################
  -- 
  --               Only Boost.Build is officially supported.
  -- 
  --                       This is not Boost.Build.
  -- 
  --  This is an alternate, cmake-based build system that is currently under development.
  --  To try it out, invoke CMake with the argument
  --         -DCMAKE_IS_EXPERIMENTAL=YES_I_KNOW
  --  Or use the gui to set the variable CMAKE_IS_EXPERIMENTAL to some value.
  --  This will only be necessary the first time.
  --  
  --  For more information on boost-cmake see the wiki:
  --      https://svn.boost.org/trac/boost/wiki/CMake
  -- 
  --  Subscribe to the mailing list:
  --      http://lists.boost.org/mailman/listinfo.cgi/boost-cmake
  -- 
  --  NOTE:  Please ask questions about this build system on the boost-cmake list,
  --         not on other boost lists.
  -- 
  --  And/or check the archives:
  --      http://news.gmane.org/gmane.comp.lib.boost.cmake
  -- 
  -- ##########################################################################
  CMake Error at CMakeLists.txt:61 (message):
    Magic variable CMAKE_IS_EXPERIMENTAL unset.
  
  
  -- Configuring incomplete, errors occurred!

Again, f you see this, just set that guard variable to something, to
demonstrate your tenacity and dedication.  Then things will work fine.

.. rubric:: Quick and dirty HOWTO

::

  % mkdir /tmp/boost
  % cd /tmp/boost
  % svn co https://svn.boost.org/svn/boost/tags/release/Boost_1_38_0 src
  % mkdir build
  % cd build
  % cmake -DCMAKE_IS_EXPERIMENTAL=ORLY -DCMAKE_INSTALL_PREFIX=/path/to/installdir ../src

At this point, you have two options: you either want to leave boost in
place and use it there, or you want to install it to a particular
location.  

**In-place**

  If you're competent to specify header/library paths
  yourself and want to build in place::
  
    % make
  
  and your libraries will be in /tmp/boost/build/lib, and the headers in
  /tmp/boost/src, (where you'd expect them to be).
  
**Installed to some location**

  This will install boost to ``lib/`` and ``include/`` under the
  ``CMAKE_INSTALL_PREFIX`` given above::
  
    % make modularize   # shuffles some headers around
    % make install

.. warning:: 

   In versions 1.38 and 1.39, if you want to ``make install``, you
   *must* ``make modularize`` first.  This is an intermediate step
   that we expect to go away in future versions.

Also note that cmake supports ``DESTDIR`` for making .deb and .rpm
packages;  see the standard cmake documentation 

Known Issues
^^^^^^^^^^^^

* There isn't much support for building/running tests within boost in
  these releases.
* In version 1.39, the ``BOOST_VERSION_MINOR`` is wrong: it is set to
  1.38.  You can set this manually by looking for
  ``BOOST_VERSION_MINOR`` in the toplevel ``CMakeLists.txt``
* The boost build names the ``boost_prg_exec_monitor`` and
  ``boost_unit_test_framework`` libraries with an additional trailing
  ``-s``.  You will probably need to modify your build if you use
  these libraries.


1.35.0 - 1.37
-------------

There was a CMake branch that built these releases, but Boost.CMake
was not included in the official distribution.

