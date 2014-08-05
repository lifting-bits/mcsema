..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

.. _find_package: http://www.cmake.org/cmake/help/cmake-2-8-docs.html#command:find_package
.. _FindBoost.cmake: http://www.cmake.org/cmake/help/cmake-2-8-docs.html#module:FindBoost

.. _CMAKE_PREFIX_PATH: http://www.cmake.org/cmake/help/cmake-2-8-docs.html#variable:CMAKE_PREFIX_PATH

.. _CMAKE_INSTALL_PREFIX: http://www.cmake.org/cmake/help/cmake-2-8-docs.html#variable:CMAKE_INSTALL_PREFIX

.. index:: targets, exported
.. index:: uninstalled tree, building against
.. _exported_targets:


Tricks for Building against Boost with CMake
============================================

Boost.CMake *exports* its targets, making developing independent
projects against an installed boost, or simply against a build tree
sitting on disk.  There are a variety of ways to use these to ease
configuration of boost in your external project.

.. index:: Building against uninstalled boost
.. _uninstalled:

With an uninstalled build
^^^^^^^^^^^^^^^^^^^^^^^^^

You only need to do three things:

1.  Add the appropriate include directory with
    ``include_directories()``.  This is the toplevel of the boost
    source tree.

2.  ``include`` the generated ``Exports.cmake`` from the build tree
    containing the exported targets.  I is located in
    ``${``:ref:`CMAKE_BINARY_DIR`\ ``}/lib/Exports.cmake``

3.  Tell cmake about your link dependencies with
    ``target_link_libraries``.  Note that you use the **names of the
    cmake targets**, not the shorter names that the libraries have on
    disk.   ``make help`` shows a list::

       % make help | grep signals
       ... boost_signals
       ... boost_signals-mt-shared
       ... boost_signals-mt-shared-debug
       ... boost_signals-mt-static
       ... boost_signals-mt-static-debug
              
    See also :ref:`name_mangling` for details on the naming
    conventions.

Since these are exported targets, CMake will add appropriate *rpaths*
as necessary; fiddling with ``LD_LIBRARY_PATH`` should not be
necessary.

**If you get the target name wrong**, cmake will assume that you are
talking about a library in the linker's default search path, not an
imported target name and you will get an error when cmake tries to
link against the nonexistent target.  For instance, if I specify::

  target_link_libraries(main boost_thread-mt-d)

on linux my error will be something like::

  [100%] Building CXX object CMakeFiles/main.dir/main.cpp.o
  Linking CXX executable main
  /usr/bin/ld: cannot find -lboost_thread-mt-d
  collect2: ld returned 1 exit status

The problem here is that the real name of the multithreaded, shared,
debug library **target** is ``boost_thread-mt-shared-debug``.  I know this is
confusing; much of this is an attempt to be compatible with
boost.build.

If you are having trouble, have a look inside that file
``Exports.cmake``.  For each available target, you'll see::

  # Create imported target boost_thread-mt-shared-debug
  ADD_LIBRARY(boost_thread-mt-shared-debug SHARED IMPORTED)
  
  # Import target "boost_thread-mt-shared-debug" for configuration "Release"
  SET_PROPERTY(TARGET boost_thread-mt-shared-debug APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
  SET_TARGET_PROPERTIES(boost_thread-mt-shared-debug PROPERTIES
    IMPORTED_LINK_INTERFACE_LIBRARIES_RELEASE "pthread;rt"
    IMPORTED_LOCATION_RELEASE "/home/troy/Projects/boost/cmake/cmaketest/build/boost/lib/libboost_thread-mt-d.so.1.41.0"
    IMPORTED_SONAME_RELEASE "libboost_thread-mt-d.so.1.41.0"
    )
  
it is the name in the ``ADD_LIBRARY`` line that you pass to
``target_link_libraries()``.



Example
-------

There is an unpacked boost in ``/home/troy/boost-1.41.0/src`` and
built boost in directory ``/home/troy/boost/1.41.0/build``. I have a
program that builds from one file, ``main.cpp`` and uses boost
threads.  My ``CMakeLists.txt`` looks like this::

   include_directories(
     /home/troy/boost-1.41.0/src
     /home/troy/boost-1.41.0/build/lib/Exports.cmake
     )

   add_executable(my_program main.cpp)

   target_link_libraries(my_program boost_thread-mt-shared-debug)

When I build, I see
(wrapped, and some output replaced with ... for brevity)::

  % make VERBOSE=1
  ...
  [100%] Building CXX object CMakeFiles/main.dir/main.cpp.o
  /usr/bin/c++ -I/home/troy/boost-1.41.0/src -o CMakeFiles/main.dir/main.cpp.o -c /home/troy/myproject/main.cpp
  ...
  linking CXX executable main
  /usr/bin/c++ -fPIC CMakeFiles/main.dir/main.cpp.o -o main -rdynamic /home/troy/boost-1.41.0/build/lib/libboost_thread-mt-d.so.1.41.0 -lpthread -lrt -Wl,-rpath,/home/troy/boost-1.41.0/build/lib 
  ...
  [100%] Built target main

With an installed boost
^^^^^^^^^^^^^^^^^^^^^^^

The process by which cmake discovers an installed boost is a big
topic, outside the scope of this document.  Boost.CMake makes every
effort to install things cleanly and behave in a backwards-compatible
manner.  

.. index:: CMAKE_PREFIX_PATH
.. index:: CMAKE_INSTALL_PREFIX
.. index:: BOOST_INSTALL_CMAKE_DRIVERS

The variable :ref:`BOOST_INSTALL_CMAKE_DRIVERS` controls whether
Boost.CMake installs two files which help out in case multiple
versions of boost are installed.  If there is only one version
present, the situation is simpler: typically this is simply a
matter of either installing boost to a directory that on cmake's
built-in CMAKE_PREFIX_PATH_, or adding the directory to
CMAKE_PREFIX_PATH_ in your environment if it is not.  You can see
built-in search path by running ``cmake --system-information`` and
looking for ``CMAKE_SYSTEM_PREFIX_PATH``.

Try this first
--------------

Make a subdirectory for your project and create a file ``main.cpp``::

  #include <iostream>
  #include <boost/version.hpp>
  #include <boost/thread/thread.hpp>
  
  void helloworld()
  {
      std::cout << BOOST_VERSION << std::endl;
  }
  
  int main()
  {
      boost::thread thrd(&helloworld);
      thrd.join();
  }
  
.. index:: NO_MODULE

Create a ``CMakeLists.txt`` in the same directory containing the
following::

  find_package(Boost 1.41.0 COMPONENTS thread NO_MODULE)   
                                              ^^^^^^^^^--- NOTE THIS
  include(${Boost_INCLUDE_DIR})
  add_executable(main main.cpp)
  target_link_libraries(main ${Boost_LIBRARIES})

The ``NO_MODULE`` above is currently **required**, pending updates to
FindBoost.cmake_ in a cmake release. 

Then run ``cmake .`` in that directory (note the dot).  Then run make.
If all is well you will see::

  % make VERBOSE=1
  ...
  [100%] Building CXX object CMakeFiles/main.dir/main.cpp.o
  /usr/bin/c++    -I/usr/local/boost-1.41.0/include   -o CMakeFiles/main.dir/main.cpp.o -c /home/troy/Projects/boost/cmake/proj/main.cpp
  ...
  Linking CXX executable main
  /usr/bin/c++     -fPIC CMakeFiles/main.dir/main.cpp.o  -o main -rdynamic /usr/local/boost-1.41.0/lib/libboost_thread-mt-d.so.1.41.0 -lpthread -lrt -Wl,-rpath,/usr/local/boost-1.41.0/lib 
  ...
  [100%] Built target main

If all is not well, set CMAKE_PREFIX_PATH_ in your environment or in
your ``CMakeLists.txt``.  Add the CMAKE_INSTALL_PREFIX_ that you used
when you installed boost::

  export CMAKE_PREFIX_PATH=/my/unusual/location

and try again.  

Alternative: via Boost_DIR
--------------------------

If the above didn't work, you can help cmake find your boost
installation by setting ``Boost_DIR`` (in your ``CMakeLists.txt`` to
the :ref:`BOOST_CMAKE_INFRASTRUCTURE_INSTALL_DIR` that was set when you
compiled.  ``Boost_DIR`` will override any other settings.

Given a (versioned) boost installation in ``/net/someplace``, 
Your CMakeLists.txt would look like this::

  include_directories(/net/someplace/include/boost-1.41.0)
  
  # you can also set Boost_DIR in your environment
  set(Boost_DIR /net/someplace/share/boost-1.41.0/cmake)

  find_package(Boost NO_MODULE)
  
  add_executable(main main.cpp)
  
  target_link_libraries(main boost_thread-mt-shared-debug)
  

Multiple versions of boost installed
------------------------------------

The only recommended way to do this is the following:

* Install all versions of boost to the same CMAKE_INSTALL_PREFIX_. One
  or more of them must have been installed with
  :ref:`BOOST_INSTALL_CMAKE_DRIVERS` on.  :ref:`INSTALL_VERSIONED`
  should be `OFF` for one of them at most.

* Add the setting for CMAKE_INSTALL_PREFIX_ to CMAKE_PREFIX_PATH_, if
  it is nonstandard.

* Pass ``NO_MODULE`` to find_package_ when you call it (as above).

At this point passing a version argument to find_package_ (see also
docs for FindBoost.cmake_) should result in correct behavior.

.. rubric:: Footnotes

.. [#libsuffix] If your distribution specifies a :ref:`LIB_SUFFIX`
   		(e.g. if it installs libraries to
   		``${``:ref:`CMAKE_INSTALL_PREFIX`\ ``/lib64``, you
   		will find `Boost.cmake` there.  If the installation is
   		'versioned', the ``Boost.cmake`` file may be in a
   		versioned subdirectory of lib, e.g. ``lib/boost-1.41.0``.
