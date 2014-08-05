..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

.. _install_customization:

Customizing the install
=======================

Here you'll find ways to customize your installation.  If you're
trying to make the install play nice with cmake's ``find_package``,
see :ref:`find_package_boost`.

.. index:: CMAKE_INSTALL_PREFIX
   single:  installation

.. _cmake_install_prefix:

CMAKE_INSTALL_PREFIX
--------------------

This is a standard cmake option that sets the path to which boost
will be installed.

.. index:: DESTDIR

CMake generates makefiles that play nice with ``DESTDIR``.  e.g.
if you configure like this::

  cmake ../src -DCMAKE_INSTALL_PREFIX=/tmp/blah

and install with ``DESTDIR=/foo make install``, you'll get files
installed to ``/foo/tmp/blah``.

.. index:: LIB_SUFFIX
.. _lib_suffix:

LIB_SUFFIX
----------

This defines the subdirectory of ``CMAKE_INSTALL_PREFIX`` to which
libraries will be installed.  It is empty by default. For example,
if I'm on 64-bit fedora, I want the libs installed to
``/usr/lib64``, I'd use::

  cmake ../src -DCMAKE_INSTALL_PREFIX=/usr -DLIB_SUFFIX=64

.. index:: INSTALL_VERSIONED
.. _install_versioned:

INSTALL_VERSIONED
-----------------

**ON** by default on unix, **OFF** on windows.

This is a different mangling than :ref:`WINMANGLE_LIBNAMES`: this
variable controls whether boost versions will be mangled into the
paths into which boost is installed.  This option **has effect only
when CMake is run the first time**: they will be set as explained
below the first time thereafter not modified, so that the paths are
customizable by users.  (ie If you have configured a build and change
this option, it will have no effect, you must start "from scratch")

.. rubric:: Example

For boost version 1.41.0, with this option ON, the installation tree
is::

  $CMAKE_INSTALL_PREFIX/
    include/
      boost-1.41.0/
        boost/
          version.hpp 
          ...
    lib/    
      boost-1.41.0/
        libboost_signals-mt-d.so
        ...

and without it, ::

  $CMAKE_INSTALL_PREFIX/
    include/
      boost/
        version.hpp 
        ...
    lib/
      boost/
        libboost_signals-mt-d.so
        ...
   
**Note:** ``lib/`` above will contain :ref:`LIB_SUFFIX` if set.

See also :ref:`BUILD_SOVERSIONED`

The relative lib and include pathnames can be controlled individually
with the following two variables:

.. index:: BOOST_LIB_INSTALL_DIR
.. _boost_lib_install_dir:

BOOST_LIB_INSTALL_DIR
---------------------

The directory to which libs will be installed under
:ref:`CMAKE_INSTALL_PREFIX`.

.. index:: BOOST_INCLUDE_INSTALL_DIR
.. _boost_include_install_dir:

BOOST_INCLUDE_INSTALL_DIR
-------------------------

The directory to which boost header files will be installed under
:ref:`CMAKE_INSTALL_PREFIX`.

.. index:: BOOST_CMAKE_INFRASTRUCTURE_INSTALL_DIR
.. _boost_cmake_infrastructure_install_dir:

BOOST_CMAKE_INFRASTRUCTURE_INSTALL_DIR
--------------------------------------

This is a directory to which the targets from this boost install will
be exported, by default ``${CMAKE_INSTALL_PREFIX}/share/boost-``\
|version|\ ``/cmake``: this significanly eases detection of boost
installations by CMake.  The name of the files are
``BoostConfig.cmake`` and ``BoostConfigVersion.cmake`` [#findpackage]_. 
See :ref:`exported_targets` for
more information about how users employ this file.

If this is a full path, it will be used directly, otherwise it will be
interpreted relative to ``${CMAKE_INSTALL_PREFIX}``.

.. index:: BOOST_INSTALL_CMAKE_DRIVERS
.. _boost_install_cmake_drivers:

BOOST_INSTALL_CMAKE_DRIVERS
---------------------------

Specifies whether generic cmake driver files should be installed, 
see the next option to customize where.  This variable is
``ON`` by default.  

BOOST_CMAKE_DRIVERS_INSTALL_DIR
-------------------------------

There are two optional version-agnostic driver files that can be
installed to a central location, by default
``${CMAKE_INSTALL_PREFIX}/share/boost-``\ |version|\ ``/cmake``.  

named ``BoostConfig.cmake`` and ``BoostConfigVersion.cmake``.  These
two files coordinate with Boost-|version|.cmake to enable cmake
developers who use both boost and cmake to find local boost
installations via the standard cmake incantation::

  find_package(Boost 1.41.0 COMPONENTS thread iostreams)

These driver files should be the same from release to release.  

This variable allows modification of this location; If this is a full
path, it will be used directly, otherwise it will be interpreted
relative to ``${CMAKE_INSTALL_PREFIX}``.

.. index:: BOOST_EXPORTS_FILE
.. _BOOST_EXPORTS_FILE:

BOOST_EXPORTS_FILE
------------------

This is the path *in the build tree* to the file that will contain
CMake exported targets, by default it is::

  ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/Exports.cmake

See :ref:`exported_targets` for information on how to use this handy
file when building against an **uninstalled** boost.  *This variable
has no effect on installation, and is only useful if building separate
cmake projects against an uninstalled boost.* 

If this is a full path, it will be used directly, otherwise it will be
interpreted relative to ``${CMAKE_BINARY_DIR}``.

.. index:: BOOST_INSTALL_EXPORTS_FILE
.. _BOOST_INSTALL_EXPORTS_FILE:

BOOST_EXPORTS_INSTALL_DIR
-------------------------

This is the path to which exported targest will be installed. By
default it is ``${BOOST_LIB_INSTALL_DIR}``.  This must be a
**relative** path.

See :ref:`exported_targets` for information on how to use this handy
file to build against an **installed** boost.   



.. rubric:: Footnotes

.. [#findpackage] See also the cmake docs for ``find_package()``. 
