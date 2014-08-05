..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

.. index:: variants
.. index:: features

.. _VARIANTS:
.. _features:

Build Variants and Features
===========================

Different compilation and linking flags affect how source code and
libraries are compiled. Boost's build system abstracts some of these
properties into specific *features* of the build, which indicate (at
a high level) what options are being used, e.g., multi-threaded,
release-mode, shared libraries, etc. Each feature brings with it
certain compilation options (which vary from one compiler to the next)
that need to be used when building that variant. For example, on Unix
systems, one often must link against the `pthread` library for
multi-threaded programs and libraries, which requires the addition of
the `-lpthread` flag to the link line. The ''features'' feature of the
build system encapsulates this knowledge.

A library built with a given set of **features** is called a library
**variant**. For example, we could have a multi-threaded release variant
of a shared library, which would be built with all of the options
needed to support multi-threading, optimization, elimination of
debugging symbols, and for building a shared library. Each variant of
a library is given a unique name based on the features in that
variant, so that one can readily identify the library, for example,
`libboost_signals-gcc40-mt-d.so` is the multi-threaded, debug version
of the shared library for Boost.Signals on a typical Linux system. The
`Boost Getting Started guide
<http://www.boost.org/more/getting_started/windows.html#library-naming>`_
describes the library naming conventions used for the variants.

The configuration and build of the library for each *feature* is
(dis|en)abled with a boolean option ``ENABLE_``\ *feature*, which set
in :ref:`cmakecache.txt`.  The available features are:

.. _name_mangling:

Name Mangling
-------------

Libraries have their features mangled in to distinguish the variants
from one another.  CMake's symbolic target names correspond:

============== ===========   ======================
Feature        Target Name   Library Name Component
============== ===========   ======================
shared         -shared       (none)
static         -static       (none)
multithreaded  -mt           -mt
release        (none)        (none)
debug          -debug        -d
pydebug        -pydebug      -yd
============== ===========   ======================

The make target ``help`` will show the available options::

  ``make help`` shows a list::

  % make help | grep signals
  ... boost_signals
  ... boost_signals-mt-shared
  ... boost_signals-mt-shared-debug
  ... boost_signals-mt-static
  ... boost_signals-mt-static-debug
  ... boost_signals-shared
  ... boost_signals-shared-debug
  ... boost_signals-static
  ... boost_signals-static-debug
           
And you can see the correspondence to the libraries on disk::

  % ls lib/libboost_signals*
  lib/libboost_signals-d.a              lib/libboost_signals-mt.a
  lib/libboost_signals-d.so             lib/libboost_signals-mt.so
  lib/libboost_signals-mt-d.a           lib/libboost_signals.a
  lib/libboost_signals-mt-d.so          lib/libboost_signals.so
    
(Note: on most unix you will see more than this, as some of them
contain version numbers and are symbolic links to one another).

Configuring features
--------------------

You can globally (en|dis)able the build of these various features
through the following cmake variables:

.. index:: 
   single: ENABLE_STATIC
   pair: STATIC; feature

.. _enable_static:

ENABLE_STATIC
^^^^^^^^^^^^^

  The `STATIC` feature identifies static builds of libraries, i.e., a
  `.lib` (library) file on Microsoft Windows or a `.a` (archive) file
  on Unix systems.

.. index:: 
   single: ENABLE_SHARED
   pair: SHARED; feature

ENABLE_SHARED
^^^^^^^^^^^^^

  The `SHARED` feature identifies shared builds of libraries, i.e.,
  a `.dll` (dynamically linked library) file on Microsoft Windows or
  a `.so`(shared object) or `.dylib` (dynamic library) file on Unix
  systems. In some cases, `SHARED` variants actually refer to
  "modules", which are a special kind of shared library on some
  systems (e.g., Mac OS X).

.. index:: 
   single: ENABLE_DEBUG
   pair: DEBUG; feature

ENABLE_DEBUG
^^^^^^^^^^^^

  The `DEBUG` feature identifies builds of libraries that retain
  complete debugging information and prohibit optimization, making
  these builds far easier to use for debugging programs.

.. index::
   single: ENABLE_RELEASE
   pair: RELEASE; feature

ENABLE_RELEASE
^^^^^^^^^^^^^^

  The `RELEASE` feature identifies builds of libraries that use full
  optimization and eliminate extraneous information such as debug
  symbols, resulting in builds of libraries that are typically much
  smaller than (and execute faster than) their debug library
  counterparts.


.. index::
   single: ENABLE_SINGLE_THREADED
   pair: SINGLE_THREADED; feature
    
ENABLE_SINGLE_THREADED
^^^^^^^^^^^^^^^^^^^^^^

  The `SINGLE_THREADED` feature identifies builds of libraries that
  assume that the program using them is single-threaded. These
  libraries typically avoid costly atomic operations or locks, and
  make use of no multi-threaded features.


.. index::
   single: ENABLE_MULTI_THREADED
   pair: MULTI_THREADED; feature

ENABLE_MULTI_THREADED
^^^^^^^^^^^^^^^^^^^^^

  The `MULTI_THREADED` feature identifies builds of libraries that
  assume that the program using them is multi-threaded. These
  libraries may introduce additional code (relative to their
  single-threaded variants) that improves the behavior of the
  library in a multi-threade context, often at the cost of
  single-thread performance.


.. index::
   single: ENABLE_STATIC_RUNTIME
   pair: STATIC_RUNTIME; feature

ENABLE_STATIC_RUNTIME
^^^^^^^^^^^^^^^^^^^^^

  The `STATIC_RUNTIME` feature identifies builds that link against
  the C and C++ run-time libraries statically, which directly
  includes the code from those run-time libraries into the Boost
  library or executable.


.. index::
   single: ENABLE_DYNAMIC_RUNTIME
   pair: DYNAMIC_RUNTIME; feature

ENABLE_DYNAMIC_RUNTIME
^^^^^^^^^^^^^^^^^^^^^^

  The `DYNAMIC_RUNTIME` feature identifies builds that link against
  the dynamic C and C++ run-time libraries.

.. _per_feature_flags:

Per-feature Compilation and Linker Options
------------------------------------------

For each feature above, the Boost build system defines three variables
used to provide compilation flags, linking flags, and extra libraries
to link against when using that feature.  These flags are automatically
added to the build commands for variants using that feature. The
particular flags and libraries are described by the following global
variables:

feature_COMPILE_FLAGS
^^^^^^^^^^^^^^^^^^^^^

  A string containing extra flags that will be added to the compile
  line, including macro definitions and compiler-specific flags
  needed to enable this particular feature.

feature_LINK_FLAGS
^^^^^^^^^^^^^^^^^^

  A string containing extra flags that will be added to the
  beginning of the link line. Note that these flags should '''not'''
  contain extra libraries that one needs to link against. Those
  should go into `feature_LINK_LIBS`.

feature_LINK_LIBS
^^^^^^^^^^^^^^^^^

  A CMake list containing the names of additional libraries that
  will be linked into libraries and executables that require this
  feature. The elements in this list should name the library (e.g.,
  `pthread`) rather than providing the link command itself (e.g.,
  `-lpthread`), so that linking will be more portable.

Each of these variables can be expanded for any feature, e.g.,
`MULTI_THREADED_LINK_LIBS` contains libraries that multi-threaded
variants should link against.

All of the flags provided for each feature are typically detected by
the Boost CMake configuration module in
``tools/build/CMake/BoostConfig.cmake``.

.. note:: These are **global** per-feature flags, ie
   	  RELEASE_COMPILE_FLAGS defines flags used for the compilation
   	  of all ``.cpp`` files that go into release libraries.  See
   	  :ref:`boost_add_library_macro` for per-feature flags that apply only to
   	  individual libraries.

Default Variants
----------------

By default, Boost's build system will build every permutation of
libraries in the feature space 

  (`STATIC` or `SHARED`) x (`DEBUG` or `RELEASE`) x 
  (`SINGLE_THREADED` or `MULTI_THREADED`)

resulting in 8 different copies of each library, modulo certain cases
where variants are disabled [#disabled_variants]_. On Windows, where
the distinction between static and dynamic run-time libraries is very
important, the default build also creates permutations with
(`STATIC_RUNTIME` or `DYNAMIC_RUNTIME`). Certain non-sensical
combinations of libraries will automatically be eliminated, e.g., it
does not generally make sense to create a shared library that links
against the static C and C++ run-time libraries. However, this still
means that the default build creates between 8 and 12 different
variants of each Boost library.

Users who only need a few variants of each library can change which
variants of Boost libraries are build by default using various
configuration options. For each feature, CMake's configuration will
contain an option `ENABLE_feature`. When the feature is ON, the build
system will produce variants with that feature. When the feature is
OFF, the build system will suppress variants with that feature. For
example, toggling `ENABLE_DEBUG` to `OFF` will inhibit the creation of
the debug variants, drastically improving overall build times.

.. rubric:: Footnotes

.. [#disabled_variants] For instance, the **SINGLE_THREADED** variant
   			of the *boost_thread* project is disabled.
