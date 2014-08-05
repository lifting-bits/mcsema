..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

.. highlight:: git_shell

.. _hacking_cmake_with_git:

Hacking Boost.CMake with Git
============================

Boost-cmake, in addition to using an alternative build system, uses
alternate version control.  This makes boost.cmake feasable: without
distributed version control it would be very difficult to maintain a
build system against upstream boost.

This document will review some common version-control procedures for
those who are unfamiliar with git.  More documentation is available at
`Hacking Boost via Git
<http://gitorious.org/boost/git-docs/blobs/raw/master/build/html/index.html>`_.


The first step is to get `Git <http://git-scm.com>`_.  Any recent
version will do.  On windows, git downloads come with a bash shell, so
the commandline interface is essentially identical.  There is also
`TortoiseGit <http://code.google.com/p/tortoisegit/>`_, which is
evolving quickly and quite usable.

I just want to try the HEAD of the <whatever> branch
----------------------------------------------------

Pick some directory to work in.  Here I'll use ``/tmp``.  My prompt is
a percent sign.  Clone the repository to a subdirectory called
``src``.  This will take a while the first time, after that things
will be very fast.

::

  % git clone git://gitorious.org/boost/cmake.git src
  Initialized empty Git repository in /tmp/src/.git/
  remote: Counting objects: 425396, done.
  remote: Compressing objects: 100% (129689/129689), done.
  remote: Total 425396 (delta 298454), reused 419119 (delta 292368)
  Receiving objects: 100% (425396/425396), 135.56 MiB | 1260 KiB/s, done.
  Resolving deltas: 100% (298454/298454), done.
  Checking out files: 100% (23865/23865), done.
  
inside this directory you'll see the branch that is checked out::

  % cd src       
  % git branch -l
  * 1.41.0
  
This means I'm on the ``1.41.0`` branch, and the files are checked
out::

  % ls
  CMakeLists.txt     boost/           bootstrap.sh*  libs/    tools/
  CTestConfig.cmake  boost-build.jam  build/         more/    wiki/
  INSTALL            boost.css        doc/           people/
  Jamroot            boost.png        index.htm      rst.css
  LICENSE_1_0.txt    bootstrap.bat    index.html     status/

Now you can go ahead and do your out-of-source build.  

I want to svn update
--------------------

When new changes arrive upstream, you'll want to ``git pull``::

  % git pull
  remote: Counting objects: 310, done.
  remote: Compressing objects: 100% (45/45), done.
  remote: Total 205 (delta 154), reused 203 (delta 152)
  Receiving objects: 100% (205/205), 49.59 KiB, done.
  Resolving deltas: 100% (154/154), completed with 81 local objects.
  From git://gitorious.org/boost/cmake
     1818334..b945719  1.41.0     -> origin/1.41.0
  Updating 1818334..b945719
  Fast forward
   CMakeLists.txt                                     |    6 +-
   CTestConfig.cmake                                  |    5 +-
  ...
   83 files changed, 1071 insertions(+), 537 deletions(-)

.. _makeremote:

But I want a different branch than that
---------------------------------------

``git branch -r`` will show your 'remote' branches::

  % git branch -r
    origin/1.40.0
    origin/1.41.0
    origin/HEAD -> origin/1.41.0
    origin/master

This shows that in *origin* (the repository you cloned from), there
are *1.40.0*, *1.41.0*, and *master* branches.  To switch to e.g. the
*1.40.0* branch, you make a local branch that 'tracks' the upstream
branch::

  % git checkout -b 1.40.0 origin/1.40.0
  Branch 1.40.0 set up to track remote branch 1.40.0 from origin.
  Switched to a new branch '1.40.0'

Now you will see this new local branch in your branch list::

  % git branch -l
  * 1.40.0   # the star means this one is checked out
    1.41.0
   
And your status will show it as well::

  % git status
  # On branch 1.40.0
  nothing to commit (working directory clean)

now, any *git pull*\ -ing you do will come from the upstream *1.40.0*
branch in to your local 1.40.0 branch.

I have changes, how do I make a patch?
--------------------------------------

Just change the files and ``git diff``::

  % git diff 
  diff --git a/CMakeLists.txt b/CMakeLists.txt
  index d2bc809..d5e055e 100644
  --- a/CMakeLists.txt
  +++ b/CMakeLists.txt
  @@ -27,6 +27,10 @@
   cmake_minimum_required(VERSION 2.6.4 FATAL_ERROR)
   project(Boost)
   
  +#
  +# These are my changes
  +#
  +
   ##########################################################################
   # Version information                                                    #
   ##########################################################################
  @@ -323,6 +327,7 @@ endif()
   
   mark_as_advanced(BOOST_EXPORTS_FILE BOOST_INSTALL_EXPORTS_FILE)
   
  +# and some here too
   # Add build rules for documentation
   add_subdirectory(doc)
   
and mail it in.

Oops, I screwed up and want to revert
-------------------------------------

Use ``git reset``::

  % git reset --hard HEAD
  HEAD is now at e26008e Don't build tools by default.  All they do is break.

I want to switch branches
-------------------------

If you've already created a local branch, i.e. it appears in the
output of ``git branch -l``::

  % git branch -l
  * 1.40.0
    1.41.0

Then just check it out::

  % git checkout 1.41.0
  Switched to branch '1.41.0'

  % git branch -l
    1.40.0
  * 1.41.0

  % git status
  # On branch 1.41.0
  nothing to commit (working directory clean)
  
If not (i.e. it only appears in the output of ``git branch -r``),
see :ref:`makeremote`.
