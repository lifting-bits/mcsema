..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

.. _add_compiled_library:

Adding a Compiled Library to CMake
==================================

This page describes how to add a new, compiled library to the
CMake-based build system. If your library is a "header-only" library,
and does not require separate compilation of object files into a
library binary, you can safely skip this step. Before adding compiled
libraries to CMake, make sure you have already followed the directions
for :ref:`boost_library_project_macro`, so that the CMake system recognizes your
Boost library.

We will assume that your library resides in the subdirectory
``libs/libname``, and that we want to create the compiled library
``boost_libname``. We will also assume that the sources for this
library reside in the subdirectory ``libs/libname/src``. The source
directory should be listed via ``SRCDIRS`` in the use of the
:ref:`boost_library_project_macro` macro, as described in the previous
section. Follow these steps to add this new
library into Boost's build system. If your library has multiple source
directories listed after ``SRCDIRS``, follow these steps for each one.

1. Create a new file ``libs/libname/src/CMakeLists.txt`` with your
   favorite text editor. This file will contain build rules for your
   compiled library. In this file, we will create one or more
   invocations of the :ref:`boost_add_library_macro` macro, which adds a
   compiled Boost library to the CMake system. This macro provides the
   name of the library, the source files from which the library will
   be built, and any specific compiler and linker options needed to
   help build the library. Let's start by adding a simple library with
   a few source files::

     boost_add_library(libname
        mysrc1.cpp mysrc2.cpp
        )

   This invocation will build several variants of the
   ``boost_libname`` library from the source files ``mysrc1.cpp`` and
   ``mysrc2.cpp``. For example, it will build both static and shared
   library, single- and multi-threaded, debug and release, etc. This
   invocation also handles the installation of these libraries.

2. For simple libraries, that's it! Rebuilding via CMake (e.g.,
   running ``make`` or reloading and rebuilding the Boost project in
   your IDE) will build the new library, including several different
   variants for different compilation options. Your Boost library will
   also be included when the user installs Boost or builds a binary
   package of Boost. Within the CMake configuration, you will also see
   an option ``BUILD_LIBNAME``, which allows the user to decide
   whether or not to build this Boost library.

3. Many libraries will need specific compilation options when
   building, need to link against other libraries (Boost or
   otherwise), or rely on certain features of the compilation process
   to proceed. Follow the instructions in the remaining part of this
   page to address these library-specific needs.


Compilation Flags
-----------------

Many libraries require certain compilation flags when we are building
the library binaries themselves (rather than when the library headers
are included by the user). For example, we want to define the macro
``BUILDING_BOOST_LIBNAME`` when building the library. We can do so by
passing the ``COMPILE_FLAGS`` option to ``boost_add_library``::

  boost_add_library(libname
      mysrc1.cpp mysrc2.cpp
      COMPILE_FLAGS "-DBUILDING_BOOST_LIBNAME=1"
      )

Now when CMake builds the library, it will pass the flag
``-DBUILDING_BOOST_LIBNAME=1`` to the compiler.

On Windows, shared libraries are built very differently from static
libraries. In particular, when building a shared library, one needs to
be sure to export the right symbols from the DLL using
``dllexport``. When users use the shared library, these symbols will be
imported (via ``dllimport``). The typical way to handle this is to
define a macro (say, ``BOOST_LIBNAME_DYN_LINK``) when building the
shared library. This macro instructs the library headers to
``dllexport`` everything that needs to be exported. We can do this with
variant-specific compile flags, e.g., ::

  boost_add_library(libname
      mysrc1.cpp mysrc2.cpp
      COMPILE_FLAGS "-DBUILDING_BOOST_LIBNAME=1"
      SHARED_COMPILE_FLAGS "-DBOOST_LIBNAME_DYN_LINK=1"
      )
 
When building a shared library, the ``SHARED_COMPILE_FLAGS`` options
will be combined with the ``COMPILE_FLAGS`` options. When building a
static library, the ``SHARED_COMPILE_FLAGS`` options will be
ignored. There are other options that can be specified per-feature,
such as ``LINK_FLAGS`` and ``LINK_LIBS``; refer to the
:ref:`boost_add_library_macro` reference for more
information.

Linking to Other Boost Libraries
--------------------------------

Some Boost libraries depends on other Boost libraries. For example,
perhaps our library uses the Boost.Filesystem library under the
hood. We can use the ``DEPENDS`` feature of the
:ref:`boost_add_library_macro` to state which libraries our library
depends on. In this example, we'll link against ``boost_filesystem``::

  
  boost_add_library(libname
      mysrc1.cpp mysrc2.cpp
      COMPILE_FLAGS "-DBUILDING_BOOST_LIBNAME=1"
      SHARED_COMPILE_FLAGS "-DBOOST_LIBNAME_DYN_LINK=1"
      DEPENDS boost_filesystem
      )

Now, each variant of the ``boost_libname`` library will link against
the appropriate ``boost_filesystem`` library variant. Whenever
``boost_filesystem`` changes, our library will be relinked
appropriately.

Linking External Libraries/Optional Sources
-------------------------------------------

Sometimes, Boost libraries need to link against other libraries
supplied by the system. The primary challenge in linking against these
libraries is *finding* those libraries, and their associated headers,
on the system. If the library is found, we usually want to pass some
extra compilation flags to our library and add in additional
sources. Otherwise, we just skip these extra sources.

CMake already contains modules that search for many common system
libraries and tools; search the
[http://www.cmake.org/HTML/Documentation.html CMake Documentation] for
existing modules that do what you need. For example, say we want to
link against the system's ``PNG`` (portable network graphics) library.
We can use the supplied ``FindPNG`` module by adding the following
early in our ``CMakeLists.txt`` file: ::

  include(FindPNG)

Documentation for CMake modules is typically found in the module file
itself. Look into the ``Modules`` subdirectory of your CMake
installation, either in ``Program Files\CMake`` (on Windows) or
``/usr/share/cmake-version`` (on Unix variants) to find the module of
the same name. The module will typically set a variable that indicates
whether the library was found. For the ``FindPNG`` module, this variable
is called ``PNG_FOUND``. We can use this variable to optionally add
sources to a variable ``EXTRA_SOURCES``::

  include(FindPNG)
  set(EXTRA_SOURCES)
  if (PNG_FOUND)
    list(APPEND EXTRA_SOURCES png.cpp)
  endif (PNG_FOUND)


CMake modules also typically define macros specifying the include
directories needed for the library, any compile-time definitions
required to use the library, and linking information for the library
binary. For the ``FindPNG`` module, these variables are called
``PNG_INCLUDE_DIR``, ``PNG_DEFINITIONS`` and ``PNG_LIBRARY``, respectively.

The include directory should be added via the CMake
``include_directories`` macro, e.g., ::

  include_directories(${PNG_INCLUDE_DIR})

The ``PNG_DEFINITIONS`` value should be added to the ``COMPILE_FLAGS``
and the ``PNG_LIBRARIES`` value to the ``LINK_LIBS`` option to the
:ref:`boost_add_library_macro`. Using these features together, we can
search for the ``PNG`` library on the system and optionally include
PNG support into our library::

  include(FindPNG)
  set(EXTRA_SOURCES)
  if (PNG_FOUND)
    include_directories(${PNG_PNG_INCLUDE_DIR})
    list(APPEND EXTRA_SOURCES png.cpp)
  endif (PNG_FOUND)
  
  boost_add_library(libname
    mysrc1.cpp mysrc2.cpp
    ${EXTRA_SOURCES}
    COMPILE_FLAGS "-DBUILDING_BOOST_LIBNAME=1 ${PNG_DEFINITIONS}"
    LINK_LIBS "${PNG_LIBRARIES}"
    SHARED_COMPILE_FLAGS "-DBOOST_LIBNAME_DYN_LINK=1"
    DEPENDS boost_filesystem
    )

If CMake does not provide a module to search for the library you need,
don't worry! You can write your own module relatively easily,
following the examples from the CMake ``Modules`` directory or some of
the Boost-specific examples, such as
http://svn.boost.org/svn/boost/branches/release/tools/build/CMake/FindICU.cmake
For a real-life example of finding system libraries and using that
information to add optional, extra capabilities to a Boost library,
check out the build rules for the Boost.IOStreams library at
http://svn.boost.org/svn/boost/branches/release/libs/iostreams/src/CMakeLists.txt

.. index:: Variants

Build Variants
--------------

The Boost build system defines many different :ref:`VARIANTS`, which
describe specific properties of certain builds. For example, the
``SHARED`` feature indicates that we are building a shared library,
while the ``MULTI_THREADED`` feature indicates that we are building a
multi-threaded library. A specific set of features is called a
``````variant``````, e.g., ``RELEASE`` and ``MULTI_THREADED`` and
``SHARED``. By default, the CMake-based build system builds several
different variants of each Boost library.

Since some features conflict with certain libraries (a threading
library cannot be ``SINGLE_THREADED``!), one can pass additional flags
to :ref:`boost_add_library_macro` stating which features should the library
cannot be built with.  For example, say that our library cannot be
built as a multi-threaded library, because it uses thread-unsafe
routines from the underlying C library. To disable multi-threaded
variants of the library, pass the option ``NOT_MULTI_THREADED``::

  boost_add_library(libname
      mysrc1.cpp mysrc2.cpp
      COMPILE_FLAGS "-DBUILDING_BOOST_LIBNAME=1"
      SHARED_COMPILE_FLAGS "-DBOOST_LIBNAME_DYN_LINK=1"
      DEPENDS boost_filesystem
      NOT_MULTI_THREADED
      )

