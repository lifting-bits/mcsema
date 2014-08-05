..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

.. _add_boost_library_project:

Adding a Library Project
========================

This page describes how to introduce a new Boost library project into
the CMake-based build system. Any Boost library that provides a
library binary (e.g., ``boost_signals.dll``) or has regression tests
(hopefully, every Boost library!) will need to be part of the build
system.

To introduce a new library, which resides in the subdirectory
``libs/libname``, follow these steps:

1. Create a new file ``libs/libname/CMakeLists.txt`` with your
   favorite text editor. This file will contain an invocation of the
   :ref:`boost_library_project_macro`, which
   identifies each Boost library to the build system. The invocation
   of the ``boost_library_project`` will look like this::

     boost_library_project(
       Libname
       SRCDIRS src
       TESTDIRS test
       EXAMPLEDIRS test
       )
    
   where ``Libname`` is the properly-capitalization library name,
   e.g., ``Signals`` or ``Smart_ptr``. The ``SRCDIRS src`` line should
   only be present if your Boost library actually needs to compile a
   library binary; header-only libraries can skip this step. The
   ``TESTDIRS test`` line indicates that the subdirectory ``test``
   contains regression tests for your library. Every Boost library
   should have these.

2. Re-run CMake (see :ref:`quickstart`) to reconfigure the source
   tree, causing CMake to find the new Boost library. CMake can be
   re-run either from the command line (by invoking ``cmake
   /path/to/boost`` or ``ccmake /path/to/boost``) or, on Windows,
   using the CMake GUI. Once you have reconfigured and generated new
   makefiles or project files, CMake knows about your library.

3. If your library has compiled sources (i.e., it is not a header-only
   library), follow the instructions on :ref:`add_compiled_library` to
   get CMake building and installing your library.

4. If your library has regression tests (it *does* regression tests,
   right?), follow the instructions on :ref:`adding_regression_tests`
   to get CMake to build and run regression tests for your library.
