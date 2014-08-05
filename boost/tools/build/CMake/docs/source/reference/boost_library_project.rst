..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

.. index:: boost_library_project
.. _boost_library_project_macro:

boost_library_project
---------------------

Define a boost library project.

.. cmake:: boost_library_project(libname[, ...])

   :param libname: name of library to add
   :type SRCDIRS: optional
   :param SRCDIRS: srcdir1 srcdir2 ...
   :type TESTDIRS: optional
   :param TESTDIRS: testdir1 testdir2 ..
   :type EXAMPLEDIRS: optional
   :param EXAMPLEDIRS: testdir1 testdir2 ..
   :param DESCRIPTION: description
   :param AUTHORS: author1 author2
   :param MAINTAINERS: maint maint2
   :type MODULAR: optional 
   :param MODULAR:

where `libname` is the name of the library (e.g., Python,
Filesystem), `srcdir1`, `srcdir2`, etc, are subdirectories containing
library sources (for Boost libraries that build actual library
binaries), and `testdir1`, `testdir2`, etc, are subdirectories
containing regression tests.

.. A library marked MODULAR has all of its header files in its own
.. subdirectory include/boost rather than the "global" boost
.. subdirectory. These libraries can be added or removed from the tree
.. freely; they do not need to be a part of the main repository.
 
`DESCRIPTION` provides a brief description of the library, which can
be used to summarize the behavior of the library for a user. `AUTHORS`
lists the authors of the library, while `MAINTAINERS` lists the active
maintainers. If `MAINTAINERS` is left empty, it is assumed that the 
authors are still maintaining the library. Both authors and maintainers
should have their name followed by their current e-mail address in
angle brackets, with -at- instead of the at sign, e.g., ::

  Douglas Gregor <doug.gregor -at- gmail.com>

.. index:: TESTDIRS
.. _TESTDIRS:

TESTDIRS
^^^^^^^^

For libraries that have regression tests, and when testing is enabled
either by `BUILD_TESTS` containing the (lowercase) name of this
library or the string ``ALL``, the generated makefiles/project files
will contain regression tests for this library.
   
.. index:: EXAMPLEDIRS
.. _EXAMPLEDIRS:

EXAMPLEDIRS
^^^^^^^^^^^

This option specifies directories containing examples.  Examples are
just libraries/executables created with :ref:`boost_add_library_macro`
and :ref:`boost_add_executable_macro`, except they are only built if
the name of the current project is specified in :ref:`BUILD_EXAMPLES`.

.. index:: MODULAR
.. _MODULAR:

MODULAR
^^^^^^^

Currently unused.

.. rubric:: Example

The Boost.Thread library uses the following invocation of the
`boost_library_project` macro, since it has both a compiled library
(built in the "src" subdirectory) and regression tests (listed in the
"test" subdirectory)::


  boost_library_project(
    Thread
    SRCDIRS src 
    TESTDIRS test 
    DESCRIPTION "Portable threading"
    AUTHORS "Anthony Williams <anthony -at- justsoftwaresolutions.co.uk">
    )

.. rubric:: Where Defined

This macro is defined in the Boost Core module in
``tools/build/CMake/BoostCore.cmake``

