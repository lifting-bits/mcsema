..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

Boost-CMake |release|
=====================

Boost.\ `CMake <http://www.cmake.org>`_ (or :ref:`alt.boost
<alt_boost>`) is the boost distribution that all the cool kids are
using.  The effort started in earnest at `BoostCon '07
<http://www.boostcon.com>`_; by the end of which it was possible to do
a basic build of boost with cmake.  In 2009, the project moved out to
git version control.  Today, ``Boost.CMake`` is stable, mature, and
supported by the developers, a large base of expert users, and
occasionally by the authors of CMake itself.

.. index:: Mailing List, IRC

**boost-cmake mailing list**    

  http://lists.boost.org/mailman/listinfo.cgi/boost-cmake      

**IRC**             

  ``#boost-cmake`` on the `freenode network <http://freenode.net>`_

**CMake home page**

  http://www.cmake.org

**Source code**

  Boost.CMake is distributed *separately* from upstream boost.  Code
  is in a `git <http://git-scm.com>`_ repository at
  http://gitorious.org/boost/cmake.git.  These documents correspond to
  tag |release|.  See also :ref:`hacking_cmake_with_git`.

**Tarballs**

  Tarballs and zipfiles are available at
  http://sodium.resophonic.com/boost-cmake/ in subdirectory |release|.  

Users's guide
=============

.. toctree::
   :maxdepth: 3

   quickstart
   build_configuration
   build_variants
   exported_targets
   install_customization
   find_package_boost
   faq
   externals/index
   git
   diff

Developer's guide
=================

.. toctree::
   :maxdepth: 3

   individual_libraries
   add_boost_library
   add_compiled_library
   testing
   adding_regression_tests
   build_installer
   notes_by_version
   
Reference
=========

.. toctree::
   :maxdepth: 1

   reference/boost_library_project
   reference/boost_module
   reference/boost_add_library
   reference/boost_add_executable
   reference/boost_python_module
   reference/boost_additional_test_dependencies
   reference/boost_test_compile
   reference/boost_test_compile_fail
   reference/boost_test_run
   reference/boost_test_run_fail

About this documentation
========================

This documentation was created with `Sphinx
<http://sphinx.pocoo.org>`_.  

The source is in the restructuredtext files in subdirectory
``tools/build/CMake/docs/source/``.  Hack on them (see the
`documentation for Sphinx <http://sphinx.pocoo.org/contents.html>`_).
When you're ready to see the html::

  make html

Once you've written a ton of docs, push them someplace where I can see
them (or use ``git diff`` to send a patch).

Release checklist
-----------------

* Update ``BOOST_CMAKE_VERSION`` in toplevel ``CMakeLists.txt``
* Update notes by version in ``tools/build/CMake/docs/notes_by_version.rst``
* Reconfig cmake with ``BOOST_MAINTAINER`` set to ON
* set UPSTREAM_TAG in root ``CMakeLists.txt``
* make make-diff
* Rebuild docs and commit
* Tag commit with ``BOOST_CMAKE_VERSION``
* ``make do-release``
* push tag
* update wiki

.. index:: alt.boost
   single: Anarchists; Lunatics, Terrorists and
   single: Lunatics; Anarchists Terrorists and
   single: Terrorists; Anarchists Lunatics and

.. _alt_boost:

Why "alt.boost"?
----------------

The 'alt' is a reference to the ``alt.*`` Usenet hierarchy.  Here, as
in Usenet, *alt* stands for `Anarchists, Lunatics and Terrorists
<http://nylon.net/alt/index.htm>`_.  This independent effort explores
and applies alternate techniques/technologies in the areas of build,
version control, testing, packaging, documentation and release
management.  

