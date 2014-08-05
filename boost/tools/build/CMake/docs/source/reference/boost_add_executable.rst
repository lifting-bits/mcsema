..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

.. index:: boost_add_executable
.. _boost_add_executable_macro:

boost_add_executable
--------------------

Adds an executable to the build

.. cmake:: boost_add_executable(exename source1 source2 ...)

   :param source1 source2...: sourcefiles
   :param COMPILE_FLAGS flag1 flag2 ...: (optional) compile flags
   :param LINK_FLAGS flag1 flag2 ...:  (optional) link flags
   :param feature_LINK_LIBS lib1 lib2 ...:  (optional) link libraries
   :param DEPENDS dep1 dep2 ...:  (optional) intraboost dependencies
   :param OUTPUT_NAME name:  (optional) output name
   :param NO_INSTALL:  (optional) don't install

where exename is the name of the executable (e.g., "wave").  source1,
source2, etc. are the source files used to build the executable, e.g.,
cpp.cpp. If no source files are provided, "exename.cpp" will be
used.

This macro has a variety of options that affect its behavior. In
several cases, we use the placeholder "feature" in the option name
to indicate that there are actually several different kinds of
options, each referring to a different build feature, e.g., shared
libraries, multi-threaded, debug build, etc. For a complete listing
of these features, please refer to the CMakeLists.txt file in the
root of the Boost distribution, which defines the set of features
that will be used to build Boost libraries by default.

The options that affect this macro's behavior are:

.. _COMPILE_FLAGS:
.. index:: COMPILE_FLAGS

* **COMPILE_FLAGS** -- Provides additional compilation flags that will be
  used when building the executable.

.. _feature_COMPILE_FLAGS:
.. index:: feature_COMPILE_FLAGS

* **feature_COMPILE_FLAGS** -- Provides additional compilation flags that
  will be used only when building the executable with the given
  feature (e.g., ``SHARED_COMPILE_FLAGS`` when we're linking against
  shared libraries). Note that the set of features used to build the
  executable depends both on the arguments given to
  boost_add_executable (see the "feature" argument description, below)
  and on the user's choice of variants to build.

.. _LINK_FLAGS:
.. index:: LINK_FLAGS

* **LINK_FLAGS** -- Provides additional flags that will be passed to the
  linker when linking the executable. This option should not be used
  to link in additional libraries; see ``LINK_LIBS`` and ``DEPENDS``.

.. _feature_LINK_FLAGS:
.. index:: feature_LINK_FLAGS

* **feature_LINK_FLAGS** -- Provides additional flags that will be passed
  to the linker when linking the executable with the given feature
  (e.g., ``MULTI_THREADED_LINK_FLAGS`` when we're linking a multi-threaded
  executable).

.. _LINK_LIBS:
.. index:: LINK_LIBS

* **LINK_LIBS** -- Provides additional libraries against which the
  executable will be linked. For example, one might provide "expat" as
  options to ``LINK_LIBS``, to state that the executable will link against
  the expat library binary. Use ``LINK_LIBS`` for libraries external to
  Boost; for Boost libraries, use ``DEPENDS``.

.. _feature_LINK_LIBS:
.. index:: feature_LINK_LIBS

* **feature_LINK_LIBS** -- Provides additional libraries to link against
  when linking an executable built with the given feature.

.. _DEPENDS:
.. index:: DEPENDS

* **DEPENDS** -- States that this executable depends on and links
  against a Boost library. The arguments to ``DEPENDS`` should be the
  unversioned name of the Boost library, such as
  "boost_filesystem". Like ``LINK_LIBS``, this option states that the
  executable will link against the stated libraries. Unlike ``LINK_LIBS``,
  however, ``DEPENDS`` takes particular library variants into account,
  always linking to the appropriate variant of a Boost library. For
  example, if the ``MULTI_THREADED`` feature was requested in the call to
  boost_add_executable, ``DEPENDS`` will ensure that we only link against
  multi-threaded libraries.

.. _feature:
.. index:: feature

* **feature** -- States that the executable should always be built using a
  given feature, e.g., ``SHARED`` linking (against its libraries) or
  ``MULTI_THREADED`` (for multi-threaded builds). If that feature has
  been turned off by the user, the executable will not build.

.. _NO_INSTALL:
.. index:: NO_INSTALL

* **NO_INSTALL** -- Don't install this executable with the rest of
  Boost.

.. _OUTPUT_NAME:
.. index:: OUTPUT_NAME

* **OUTPUT_NAME** -- If you want the executable to be generated
  somewhere other than the binary directory, pass the path (including
  directory and file name) via the ``OUTPUT_NAME`` parameter.

.. rubric:: Example

::

  boost_add_executable(wave cpp.cpp 
     DEPENDS boost_wave boost_program_options 
             boost_filesystem 
             boost_serialization
     )


.. rubric:: Where Defined

This macro is defined in the Boost Core module in
``tools/build/CMake/BoostCore.cmake``

