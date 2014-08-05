..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..


.. _quickstart:

Quickstart
==========

This page describes how to configure and build Boost with CMake. By
following these instructions, you should be able to get CMake,
configure a Boost build tree to your liking with CMake, and then
build, install, and package Boost libraries.

Download CMake
--------------

You can get it here:  http://www.cmake.org/HTML/Download.html

There are precompiled binaries for CMake on several different
platforms. The installation of these pre-compiled binaries is mostly
self-explanatory. If you need to build your own copy of CMake, please
see the `CMake installation instructions
<http://www.cmake.org/HTML/Install.html>`_.  

.. note::

  In these instructions, we will do things such that the Boost source
  tree (with CMake build files) is available in the directory
  ``$BOOST/src`` and that the build will happen in ``$BOOST/build``::
  
    $BOOST/
      src/     # (source checked out to here)
      build/   # (build output here) 
  
  Note that it is *not* actually necessary to set any environment
  variable ``BOOST``, this is a convention used in this document.

Checkout / download the code
----------------------------

Tarballs and zipfiles are avaiable at
http://sodium.resophonic.com/boost-cmake in subdirectory |release|.

Boost.CMake is distributed *separately* from upstream boost.  Code is
in a `git <http://git-scm.com>`_ repository at
http://gitorious.org/boost/cmake.git.  These documents correspond to
tag |release|.  You can clone the repository locally and then check out
the tag::

  git clone git://gitorious.org/boost/cmake.git src
  cd src
  git checkout <TAG>

where ``<TAG>`` is |release|

On Unix
-------

Create and change to the directory that will hold the binaries that
CMake build::

  mkdir $BOOST/build 
  cd $BOOST/build

.. _unix_configure:

Configure
^^^^^^^^^

Run the CMake configuration program, providing it with the Boost
source directory::

  cmake -DCMAKE_INSTALL_PREFIX=/somewhere $BOOST/src 

(:ref:`CMAKE_INSTALL_PREFIX` defaults to ``/usr/local`` on unix and
``C:\\Program Files\Boost`` on windows).  Replace ``/somewhere`` above
with a path you like if the defaults aren't okay.  You'll see output
from ``cmake``.  It looks somewhat like this::

  -- Check for working C compiler: /usr/bin/gcc
  -- Check for working C compiler: /usr/bin/gcc -- works
  -- Check size of void*
  -- Check size of void* - done
  -- Check for working CXX compiler: /usr/bin/c++
  -- Check for working CXX compiler: /usr/bin/c++ -- works
  -- Scanning subdirectories:
  --  + io
  --  + any
  --  + crc
  --  + mpl
  
    (etc, etc)
  
  --  + program_options
  --  + ptr_container
  --  + type_traits
  -- Configuring done
  -- Generating done
  -- Build files have been written to: $BOOST/build

The directory ``$BOOST/build`` should now contain a bunch of generated
files, including a top level ``Makefile``, something like this::

  % ls
  CMakeCache.txt           CPackConfig.cmake    Makefile  
  cmake_install.cmake      libs/                CMakeFiles/     
  CPackSourceConfig.cmake  bin/                 lib/

Build and Install
^^^^^^^^^^^^^^^^^

Now build and install boost::

  make install

You'll see::

  Scanning dependencies of target boost_date_time-mt-shared
  [  0%] Building CXX object libs/date_time/src/CMakeFiles/boost_date_time-mt-shared.dir/gregorian/greg_month.cpp.o
  [  0%] Building CXX object libs/date_time/src/CMakeFiles/boost_date_time-mt-shared.dir/gregorian/greg_weekday.cpp.o
  [  1%] Building CXX object libs/date_time/src/CMakeFiles/boost_date_time-mt-shared.dir/gregorian/date_generators.cpp.o
  Linking CXX shared library ../../../lib/libboost_date_time-mt.so
  [  1%] Built target boost_date_time-mt-shared

  (etc etc)

  [100%] Built bcp

  (etc etc)

  -- Installing: /tmp/flanboost/lib/libboost_wave-mt-d.a
  -- Installing: /tmp/flanboost/lib/libboost_wave-mt-d.so
  -- Removed runtime path from "/tmp/flanboost/lib/libboost_wave-mt-d.so"
  -- Installing: /tmp/flanboost/bin/bcp
  -- Installing: /tmp/flanboost/bin/inspect

And you're done. Once the build completes (which make take a while, if
you are building all of the Boost libraries), the Boost libraries will
be in a predictable layout under the directory passed to
:ref:`CMAKE_INSTALL_PREFIX` (default ``/usr/local``)

Windows
-------

There are two different sets of directions: visual studio, which is
quite specific, and nmake, which is much like the Unix version, above.

.. index:: Visual Studio

.. _vs_configure:

Configuration for Visual Studio
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Run CMake by selecting it from the Start menu. 

* Use the *Browse...* button next to *Where is the source code* to
  point CMake at the Boost source code in ``$BOOST\src``.
* Use the second *Browse...* button to next to *Where to build the
  binaries* to select the directory where Boost will build binaries,
  ``$BOOST\build``.
* Click *Configure* a first time to configure Boost, which will search
  for various libraries on your system and prepare the build.  CMake
  will ask you what kind of project files or make files to build. If
  you're using Microsoft Visual Studio, select the appropriate version
  to generate project files. Otherwise, you can use Borland's make
  files.  If you're using NMake, see the next section.
* On an XP box with VS9 one sees roughly this in the output window at
  the bottom::

    Check for working C compiler: cl
    Check for working C compiler: cl -- works
    Detecting C compiler ABI info
    Detecting C compiler ABI info - done
    Check for working CXX compiler: cl
    Check for working CXX compiler: cl -- works
    Detecting CXX compiler ABI info
    Detecting CXX compiler ABI info - done
    Boost version 1.41.0
    Found PythonInterp: C:/Python26/python.exe
    Found PythonLibs: C:/Python26/libs/python26.lib
    Boost compiler: msvc
    Boost toolset:  vc90
    Boost platform: windows
    Could NOT find Doxygen  (missing:  DOXYGEN_EXECUTABLE)
    Build name: msvc-9.0-windows
     + preprocessor
     + concept_check
     ...
     + units
     + wave
    Configuring done    

* The messages about 'missing doxygen' and whatnot are not
  showstoppers for now, so long as configuration is successful.  You
  will be given the opportunity to tune build options in the CMake GUI
  (see :ref:`configure_and_build` for more detail). They will
  initially appear red.  Click *Configure* again when you are done
  editing them.  The one thing that you may wish to configure as part
  of this 'quickstart' is ``CMAKE_INSTALL_PREFIX``.
* Finally, click *Generate* to generate project files.  ``Boost.sln``,
  the VS solution file, will appear in the *where to build the
  binaries* directory from the cmake gui.

.. index:: NMake
.. _NMake:

Configuration for NMake
^^^^^^^^^^^^^^^^^^^^^^^

* Start a `Visual Studio Command Prompt` from the start menu.  This
  will spawn a command prompt window with certain env variables set.
  CMake will detect these and automatically choose to generate NMake
  files.

* cd to $BOOST/build and execute::

    cmake ..\src

  You will see output very similar to that on unix, see
  :ref:`unix_configure`.

Build -- Visual Studio
^^^^^^^^^^^^^^^^^^^^^^

  Start up Visual Studio, load the solution or project ``Boost`` from
  the Boost build directory you set in the CMake configuration
  earlier. Then, just click *Build* to build all of Boost.

Build -- NMake
^^^^^^^^^^^^^^

  Execute ``nmake`` from the command prompt in the build directory.

Installation
^^^^^^^^^^^^

The installation of Boost's headers and compiled libraries uses the
same tools as building the library. With Microsoft Visual Studio, just
load the Boost solution or project and build the 'INSTALL' target to
perform the installation.  With NMake, ``nmake install``.

