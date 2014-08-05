..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

Building a Binary Installer
===========================

CMake can easily build binary installers for a variety of
platforms. On Windows and Mac OS X, CMake builds graphical
installation programs. For other Unix operating systems, CMake
currently builds tarballs and self-installing shell scripts. This
CMake functionality, provided by the
`CPack <http://www.cmake.org/Wiki/CMake:Packaging_With_CPack>`_ program
that is part of CMake, is used to create all of CMake's binary
installers. We use CPack to build binary installers for Boost. To
build a binary installer for Boost, follow these steps:

1. Build Boost using CMake.  (see :ref:`quickstart`)

2. ('''Windows only''') Download and install the `Nullsoft Scriptable
   Install System (NSIS) <http://nsis.sourceforge.net/Main_Page>`_,
   which is used to create graphical installers on Windows. Unix users
   do not need to install any extra tools.

3. Using the same development tools for building Boost, build the
   "package" target to create the binary installers.  

   * With Microsoft Visual Studio, build the target named ``PACKAGE``
   * With makefiles, run ` make package``.

The output of the packaging process will be one or more binary
packages of the form Boost-*version*\ -*platform*\ \.*extension*\ . The
type of package will differ from one platform to another:

* On Windows: The primary output is an executable (``.exe``) that
  provides a graphical installer.

* On Mac OS X: The primary output is a disk image (``.dmg``) that
  contains a graphical installer package.

* On Unix: Packaging produces compressed tarballs (``.tar.gz``) and
  a self-installing shell script (``.sh``)


Windows installer:

.. image:: WindowsInstaller.png


Mac installer:

.. image:: MacInstaller.png

