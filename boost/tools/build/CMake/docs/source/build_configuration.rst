..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

.. _configure_and_build:

Configuring the buildspace
==========================

Configuration tools
-------------------

Included in the standard cmake distribution are the Windows `CMake`
gui and the unix `ccmake` curses interface, which allow one to
configure various aspects of the cmake build.  On Microsoft Windows
run the CMake configuration program from the Start menu.  

Having done the initial configuration step as in :ref:`quickstart`,
on unix run::

  make edit_cache

in the binary directory.  On windows just run the cmake gui and choose
the binary dir from the pulldown menu.  You will be presented with a list of editable build options something
like this::

   BOOST_PLATFORM                   linux 
   BUILD_BCP                        ON 
   BUILD_BOOST_WSERIALIZATION       ON 
   BUILD_EXAMPLES                   NONE 
   BUILD_INSPECT                    ON 
   BUILD_TESTS                      NONE 
   CMAKE_BUILD_TYPE                 Release 
   CMAKE_INSTALL_PREFIX             /usr/local 
   DART_TESTING_TIMEOUT             15 
   DEBUG_COMPILE_FLAGS              -g 
   DOCBOOK_AUTOCONFIG               OFF 
   DOCBOOK_DTD_DIR                  DOCBOOK_DTD_DIR-NOTFOUND 
   DOCBOOK_XSL_DIR                  DOCBOOK_XSL_DIR-NOTFOUND 
   ENABLE_DEBUG                     ON 
   ENABLE_MULTI_THREADED            ON 
   ENABLE_RELEASE                   ON 
   ENABLE_SHARED                    ON 
   ENABLE_SINGLE_THREADED           OFF 
   ENABLE_STATIC                    ON 
   RELEASE_COMPILE_FLAGS            -O3 -DNDEBUG 
   UNZIP                            /usr/bin/unzip 
   WINMANGLE_LIBNAMES               OFF 
   XSLTPROC                         /usr/bin/xsltproc 
   XSLTPROC_FLAGS                   --xinclude 

On windows, the configurables will be right in the middle of the gui;
can't miss 'em.  Note the ``[t]`` key to toggle 'advanced mode' which
will show more options (on windows this is a selection box that says
``Simple View`` by default, pull it down to see Advanced and Grouped
views).

Use the arrow keys to select particular options.  Press :kbd:`c` (for
(c)onfigure) to perform the preliminary configuration of the CMake
build system when you are done.  When the options you have selected
have stabilized, CMake will give you the (g)enerate option. If you do
not see this option, press :kbd:`c` again to reconfigure.  Try the
:kbd:`t` key to see more options.  When you're done press :kbd:`g` to
generate makefiles and exit.

See :ref:`VARIANTS` for information about the feature-specific options
(ie ``ENABLE_whatever`` listed above.)

.. _cmakecache.txt:

CMakeCache.txt
==============

The same information is stored in a file `CMakeCache.txt` located in
the build directory.  For this reason, after you've done the initial
configuration of a build directory you can invoke `ccmake` like this::

  ccmake <path-to-build>

or have the makefiles do it for you::

  make edit_cache

The CMakeCache.txt file is hand-editable, though this is usually not
as convenient as the cmake-supplied configuration tools mentioned
above.  An excerpt of this file::

  //
  // Enable/Disable color output during build.
  //
  CMAKE_COLOR_MAKEFILE:BOOL=ON
  
  //
  // Mangle lib names for windows, e.g., boost_filesystem-gcc41-1_34
  //
  WINMANGLE_LIBNAMES:BOOL=ON
  

On unix, (?windows too?) the generated makefiles will detect if this
file has been edited and will automatically rerun the makefile
generation phase.  If you should need to trigger this regeneration
manually you may execute ::

  make rebuild_cache

.. rubric:: Deleting the cache

You may find yourself wanting to start from scratch, for instance if
you want to switch from using Visual Studio to using NMake.  To do
this, **delete the cache file**.  On windows, there is a *Delete
Cache* option in the CMake gui's *File* menu.  On unix you can simply
``rm CMakeCache.txt``.

.. index:: CMAKE_BINARY_DIR
.. _CMAKE_BINARY_DIR:

CMAKE_BINARY_DIR
----------------

This variable is set by cmake and corresponds to the toplevel of your
``build/`` directory.


.. _useful_options:

A few useful options
--------------------

CMAKE_OSX_ARCHITECTURES
^^^^^^^^^^^^^^^^^^^^^^^

  *Mac OS X users*: to build universal binaries, set this to
   ``ppc;i386``.

.. index:: WINMANGLE_LIBNAMES
.. _winmangle_libnames:

WINMANGLE_LIBNAMES
^^^^^^^^^^^^^^^^^^

This option controls whether libraries will be built with mangled-in
compiler name/version and boost version.  For example, with
``BUILD_VERSIONED`` set to ``OFF``, the signals library looks like
this::

  % ls lib/*signals*
  lib/libboost_signals-mt-d.a    lib/libboost_signals-mt.a
  lib/libboost_signals-mt-d.so*  lib/libboost_signals-mt.so*
  
But with it on, (on a gcc 4.3 linux box)::

  % ls lib/*signal*
  lib/libboost_signals-gcc43-mt-1_40.a    
  lib/libboost_signals-gcc43-mt-d-1_40.a
  lib/libboost_signals-gcc43-mt-1_40.so*  
  lib/libboost_signals-gcc43-mt-d-1_40.so*
  
Historically this mangling has been convenient for windows users and a
bane to unix users, thus *winmangle_libnames*.

.. note:: The on-disk names of library :ref:`variants <variants>` are
   	  always mangled with the active :ref:`features <features>`.
   	  ``WINMANGLED_LIBNAMES`` affects mangling of compiler and boost
   	  version only.

.. index:: BUILD_PROJECTS
.. _BUILD_PROJECTS:

BUILD_PROJECTS
^^^^^^^^^^^^^^

This is a semicolon-separated list of projects to be built, or
``"ALL"`` (the default) for all projects, or ``"NONE"``.  Projects not
appearing in this list (if list not ``"ALL"``) are ignored; no targets in
this project will appear.  Example::

  BUILD_PROJECTS=thread;python

See also the :ref:`boost_library_project_macro` macro.  

.. note::

   If you specify a project with link time dependencies on other
   projects, e.g. ``filesystem``, (which depends on ``system``) and
   omit the dependencies, you will get an error from cmake something
   like this::

      CMake Error at tools/build/CMake/BoostCore.cmake:736 (get_property):
        get_property could not find TARGET boost_system-mt-shared.  Perhaps it has
        not yet been created.
      Call Stack (most recent call first):
        tools/build/CMake/BoostCore.cmake:1170 (boost_library_variant)
        libs/filesystem/src/CMakeLists.txt:7 (boost_add_library)


.. index:: BUILD_EXAMPLES
.. _BUILD_EXAMPLES:

BUILD_EXAMPLES
^^^^^^^^^^^^^^

This is a semicolon-separated list of projects whose examples should
be built, e.g.::

  BUILD_EXAMPLES="iostreams;accumulators"

.. warning:: If you pass this on the commandline in a unix shell,
   	     don't forget to quote the list of arguments or escape the
   	     semicolons...

Per-library examples are specified with the :ref:`EXAMPLEDIRS`
argument to the :ref:`boost_library_project_macro` macro.

.. rubric:: Note:

A project's examples will only be built if the project appears in
**both** :ref:`BUILD_PROJECTS` and :ref:`BUILD_EXAMPLES`.  I.e., the
``BUILD_PROJECTS`` filter is applied first, and the ``BUILD_EXAMPLES``
filter has no ability to reverse the result. 

.. index:: BUILD_TOOLS
.. _BUILD_TOOLS:

BUILD_TOOLS
^^^^^^^^^^^

Similar to BUILD_EXAMPLES and BUILD_PROJECTS above, this is a
semicolon-separated list of tools (in subdirectory
``$BOOST_ROOT/tools/``) that should be built, e.g.::

  BUILD_TOOLS=quickbook;wave

``"ALL"`` will build all tools, ``"NONE"`` will build none.  Note that
the values here are lowercase (only subdirectories of ``tools/``
matching one of the strings in the list will be traversed by cmake).

.. index:: verbosity; CMAKE_VERBOSE_MAKEFILE

CMAKE_VERBOSE_MAKEFILE
^^^^^^^^^^^^^^^^^^^^^^

  Displays full build commands during build.  Good for debugging.
  This option will generate permanently verbose makefiles; it is
  generally easier to invoke make with the option ``VERBOSE=1``
  instead (this has the same effect, but is not persistent).

.. index:: CMAKE_CXX_COMPILER

.. _cmake_cxx_compiler:

CMAKE_CXX_COMPILER
^^^^^^^^^^^^^^^^^^

  Sets the compiler.  If you have a nonstandard compiler and no
  default compiler, you may have to pass the value of this option on
  the commandline, for example::

    cmake ../src -DCMAKE_CXX_COMPILER=gcc-4.4

  On windows you can set this in the gui, but you will probably prefer
  to have cmake generate a set of nmake or project files by choosing
  an appropriate generator.

.. index:: BUILD_SOVERSIONED
.. index:: soversion
.. index:: soname
.. _BUILD_SOVERSIONED:

BUILD_SOVERSIONED
^^^^^^^^^^^^^^^^^

Enables the setting of SOVERSION in built libraries.  If
this is on::

  % ls -l libboost_thread*.so*
  lrwxrwxrwx 1 troy troy     30 Oct 29 18:37 libboost_thread-mt-d.so -> libboost_thread-mt-d.so.1.41.0*
  -rwxr-xr-x 1 troy troy 571361 Oct 29 18:37 libboost_thread-mt-d.so.1.41.0*
  lrwxrwxrwx 1 troy troy     28 Oct 29 18:37 libboost_thread-mt.so -> libboost_thread-mt.so.1.41.0*
  -rwxr-xr-x 1 troy troy 114963 Oct 29 18:37 libboost_thread-mt.so.1.41.0*
  
  % readelf -a libboost_thread-mt.so | grep SONAME
   0x000000000000000e (SONAME)             Library soname: [libboost_thread-mt.so.1.41.0]
      
and if off::

  % ls -l lib/*signals*
  -rwxr-xr-x 1 troy troy  835522 Oct 29 15:10 lib/libboost_signals-mt-d.so*
  -rwxr-xr-x 1 troy troy  121886 Oct 29 15:10 lib/libboost_signals-mt.so*
  
(Unix only, ``ON`` by default)

This setting also determines whether libraries are *installed*
with/without soversions.  See also :ref:`INSTALL_VERSIONED`.
