..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

.. index:: boost_add_library 
.. _boost_add_library_macro:

boost_add_library
-----------------

This macro creates a new Boost library target that generates a compiled library
(.a, .lib, .dll, .so, etc) from source files. This routine will
actually build several different variants of the same library, with
different compilation options, as determined by the set of "default"
library variants.

.. cmake:: boost_add_library(libname source1 source2 ...)

   :param source1 source2 ...:  relative paths to source files
   :type COMPILE_FLAGS: optional
   :param COMPILE_FLAGS: flags to pass when compiling all variants
   :type feature_COMPILE_FLAGS: optional
   :param feature_COMPILE_FLAGS: compile flags when *feature* is on
   :type LINK_FLAGS: optional
   :param LINK_FLAGS: link flags for all variants
   :type feature_LINK_FLAGS: optional
   :param feature_LINK_FLAGS: link flags for *feature* 
   :type LINK_LIBS: optional
   :param LINK_LIBS: lib1 lib2 ...
   :type feature_LINK_LIBS: optional
   :param feature_LINK_LIBS: lib1 lib2 ...
   :type DEPENDS: optional
   :param DEPENDS: libdepend1 libdepend2 ...
   :param STATIC_TAG:
   :type MODULE: boolean
   :param MODULE:
   :type NOT_feature: boolean
   :param NOT_feature:
   :type EXTRA_VARIANTS: optional
   :param EXTRA_VARIANTS: variant1 variant2 ...

where `libname` is the name of Boost library binary (e.g.,
"boost_regex") and `source1`, `source2`, etc. are the source files used
to build the library, e.g., `cregex.cpp`.

This macro has a variety of options that affect its behavior. In
several cases, we use the placeholder "feature" in the option name
to indicate that there are actually several different kinds of
options, each referring to a different build feature, e.g., shared
libraries, multi-threaded, debug build, etc. For a complete listing
of these features, see :ref:`variants`.

The options that affect this macro's behavior are:

.. index:: COMPILE_FLAGS

COMPILE_FLAGS
^^^^^^^^^^^^^

    Provides additional compilation flags that will be
    used when building all variants of the library. For example, one
    might want to add ``"-DBOOST_SIGNALS_NO_LIB=1"`` through this option
    (which turns off auto-linking for the Signals library while
    building it).

feature_COMPILE_FLAGS
^^^^^^^^^^^^^^^^^^^^^

    Provides additional compilation flags that
    will be used only when building variants of the library that
    include the given feature. For example,
    `MULTI_THREADED_COMPILE_FLAGS` are additional flags that will be
    used when building a multi-threaded variant, while
    `SHARED_COMPILE_FLAGS` will be used when building a shared library
    (as opposed to a static library).

LINK_FLAGS
^^^^^^^^^^

    Provides additional flags that will be passed to the
    linker when linking each variant of the library. This option
    should not be used to link in additional libraries; see `LINK_LIBS`
    and `DEPENDS`.

feature_LINK_FLAGS
^^^^^^^^^^^^^^^^^^

    Provides additional flags that will be passed
    to the linker when building variants of the library that contain a
    specific feature, e.g., `MULTI_THREADED_LINK_FLAGS`. This option
    should not be used to link in additional libraries; see
    feature_LINK_LIBS.

LINK_LIBS
^^^^^^^^^

    Provides additional libraries against which each of the
    library variants will be linked. For example, one might provide
    "expat" as options to LINK_LIBS, to state that each of the library
    variants will link against the expat library binary. Use LINK_LIBS
    for libraries external to Boost; for Boost libraries, use DEPENDS.

feature_LINK_LIBS
^^^^^^^^^^^^^^^^^

    Provides additional libraries for specific
    variants of the library to link against. For example,
    `MULTI_THREADED_LINK_LIBS` provides extra libraries to link into
    multi-threaded variants of the library.

DEPENDS
^^^^^^^

    States that this Boost libraries depends on and links
    against another Boost library. The arguments to `DEPENDS` should be
    the unversioned name of the Boost library, such as
    "boost_filesystem". Like `LINK_LIBS`, this option states that all
    variants of the library being built will link against the stated
    libraries. Unlike `LINK_LIBS`, however, `DEPENDS` takes particular
    library variants into account, always linking the variant of one
    Boost library against the same variant of the other Boost
    library. For example, if the boost_mpi_python library `DEPENDS` on
    boost_python, multi-threaded variants of boost_mpi_python will
    link against multi-threaded variants of boost_python.

STATIC_TAG
^^^^^^^^^^

    States that the name of static library variants on
    Unix need to be named differently from shared library
    variants. This particular option should only be used in rare cases
    where the static and shared library variants are incompatible,
    such that linking against the shared library rather than the
    static library will cause features. When this option is provided,
    static libraries on Unix variants will have "-s" appended to their
    names. *We hope that this is a temporary solution. At
    present, it is only used by the Test library.*

MODULE
^^^^^^

    This option states that, when building a shared library,
    the shared library should be built as a module rather than a
    normal shared library. Modules have special meaning an behavior on
    some platforms, such as Mac OS X.

NO_feature
^^^^^^^^^^

    States that library variants containing a particular
    feature should not be built. For example, passing
    `NO_SINGLE_THREADED` suppresses generation of single-threaded
    variants of this library.

EXTRA_VARIANTS
^^^^^^^^^^^^^^

    Specifies that extra variants of this library
    should be built, based on the features listed. Each "variant" is a 
    colon-separated list of features. For example, passing
    EXTRA_VARIANTS "PYTHON_NODEBUG:PYTHON_DEBUG"
    will result in the creation of an extra set of library variants,
    some with the `PYTHON_NODEBUG` feature and some with the
    `PYTHON_DEBUG` feature. 

.. rubric:: Example 

The Boost.Thread library binary is built using the following
invocation of the `boost_add_library` macro. The options passed to the
macro indicate that CMake should define `BOOST_THREAD_BUILD_DLL` to 1
when building shared libraries and `BOOST_THREAD_BUILD_LIB` to 1 when
building static libraries. The `NO_SINGLE_THREADED` option inhibits
creation of any single-threaded variants of the library (which
obviously would not make sense for a threading library!). The flags
needed to compile the multi-threaded variants are automatically
added. ::

  boost_add_library(
    boost_thread
    barrier.cpp condition.cpp exceptions.cpp mutex.cpp once.cpp 
    recursive_mutex.cpp thread.cpp tss_hooks.cpp tss_dll.cpp tss_pe.cpp 
    tss.cpp xtime.cpp
    SHARED_COMPILE_FLAGS "-DBOOST_THREAD_BUILD_DLL=1"
    STATIC_COMPILE_FLAGS "-DBOOST_THREAD_BUILD_LIB=1"
    NO_SINGLE_THREADED
  )
  

This example is from ``libs/thread/src/CMakeLists.txt``.

.. rubric:: Where Defined

This macro is defined in the Boost Core module in
``tools/build/CMake/BoostCore.cmake``.


