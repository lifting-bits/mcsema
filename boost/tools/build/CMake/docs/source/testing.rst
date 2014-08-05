..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

.. _testing:

Testing
=======

Boost's CMake-based build system provides regression testing via
`CTest <http://www.cmake.org/Wiki/CMake_Testing_With_CTest>`_, which
comes as part of CMake. This regression testing system can be used by
Boost developers to test their libraries locally and also by testers
and users to submit regression tests to a `CDash server
<http://www.cdash.org/CDashPublic/index.php?project=Boost>`_, which
collects and reports regression-testing results from different
sites. This document assumes that the reader has already learned how
to build and configure Boost using CMake.

.. index:: BUILD_TESTS
.. _BUILD_TESTS:

BUILD_TESTS
-----------

The variable BUILD_TESTS is a comma-separated list of projects for
which testing will be enabled, e.g.::

  "accumulators;iostreams;variant"

or the string ``"ALL"`` for all projects, or the string
``"NONE"`` to disable testing.

.. warning:: if you pass this list from a unix shell, don't forget to
   	     enclose the whole thing in quotes or escape the
   	     semicolons.

If you re-run the CMake configuration for Boost with ``BUILD_TESTS``
set to ``ALL``, you will notice that configuration takes significantly
longer when we are building all of the regression tests.  This is due
to the very large number of toplevel targets (thousands) that are
created.  Until boost's testing scheme is reorganized to reduce this
number, we anticipate that only testing nodes will want to test ALL,
whereas developers will want to test the library under development and
those that are dependent on it.  

.. index:: NMake
.. index:: Visual Studio
.. index:: tests, running all of them

.. warning:: It is **not** recommended to set ``BUILD_TESTS`` to
   	     ``"ALL"`` when using Visual Studio generators.  A very
   	     large number (thousands) of targets are generated and
   	     this can bring VS to grinding halt.  To run all tests,
   	     choose the ``NMake`` generator, see :ref:`NMake`.

Be sure to re-configure CMake once you are done tweaking these
options, and generate makefiles or project files, as mentioned in
:ref:`quickstart`.  

If you're using a command-line configuration (nmake files, unix
makefiles) you can simplify this process by passing the value of
``BUILD_TESTS`` on the command line, e.g. ::

   cmake ../src -DBUILD_TESTS="mpi;graph_parallel"

.. note:: In Visual Studio, you should be prompted by the gui to
   reload the project.  If you're unlucky, you will be prompted a
   thousand times to reload each individual solution.  For this
   reason, our current best recommendataion is to close and reopen the
   project if you rebuild ``Boost.sln``.


Build
-----

Follow the same building process described in :ref:`quickstart`.  For
Unix users, don't forget the `-i` option to `make` (ignore errors),
and also possibly `-j 2` (or more) to run the build process in
parallel. Building all of the regression tests for the Boost libraries
can take a long time. ::

  make -j2 -i

.. note:: If you change Boost source files in a way that affects your
   	  tests, you will need to rebuild to update the libraries and
   	  test executables before moving on to the next step.

Test
----

Once regression tests have finished building,

Unix and nmake
^^^^^^^^^^^^^^

at a command prompt, ``cd`` to the Boost binary directory. Then, run
the command::

  ctest

to execute all of the regression tests. The `ctest` executable comes
with cmake.  On Unix platforms, this is the same place where `ccmake`
resides. On Windows platforms, it will be in ``C:\Program
Files\CMake X.Y\bin``. The ctest program should produce output like the
following::

  Start processing tests
  Test project /Users/dgregor/Projects/boost-darwin
    1/ 22 Testing any-any_test                    Passed
    2/ 22 Testing any-any_to_ref_test             Passed
    3/ 22 Testing function-lib_function_test      Passed
    4/ 22 Testing function-function_n_test        Passed
    5/ 22 Testing function-allocator_test         Passed
    6/ 22 Testing function-stateless_test         Passed
    7/ 22 Testing function-lambda_test            Passed
    8/ 22 Testing function-function_test_fail1 ***Failed - supposed to fail
    9/ 22 Testing function-function_test_fail2 ***Failed - supposed to fail
   10/ 22 Testing function-function_30            Passed
   11/ 22 Testing function-function_arith_cxx98   Passed
   12/ 22 Testing function-function_arith_porta   Passed
   13/ 22 Testing function-sum_avg_cxx98          Passed
   14/ 22 Testing function-sum_avg_portable       Passed
   15/ 22 Testing function-mem_fun_cxx98          Passed
   16/ 22 Testing function-mem_fun_portable       Passed
   17/ 22 Testing function-std_bind_cxx98         Passed
   18/ 22 Testing function-std_bind_portable      Passed
   19/ 22 Testing function-function_ref_cxx98     Passed
   20/ 22 Testing function-function_ref_portabl   Passed
   21/ 22 Testing function-contains_test          Passed
   22/ 22 Testing function-contains2_test         Passed

  100% tests passed, 0 tests failed out of 22

Here, we have only enabled testing of the Boost.Any and Boost.Function
libraries, by setting `BUILD_TESTS` to `any;function`.

.. warning:: Again, This ``ctest`` step runs the tests without first
   	     running a build.  If you change a source file and run the
   	     ``ctest`` step you will see that no build is invoked.

To run just a subset of the tests, pass ``-R`` and a regular
expression to ``ctest`` (see the output of ``ctest --help-full``). For
example, to run all of the Python tests, use::

  ctest -R python

There is also a ``-E`` (exclude) option which does the inverse of ``-R``.
``ctest --help`` shows the full list of options.

.. index:: targets ; testing
.. index:: testing ; targets

Visual Studio
^^^^^^^^^^^^^

You will see a solution named ``RUN_TESTS``.  Build this to run the
tests.  If you want to run them from the commandline, for some
projects you will have to use the ``-C`` flag to ctest to specify the
ctest configuration type (Debug or Release, typically).


Targets
-------

The testing subsystem adds toplevel targets to the build.  On unix you
can see them in the output of ``make help``.  For example some of the
accumulators test targets look like this::

  % make help | grep accum
  ... accumulators-tests-count
  ... accumulators-tests-covariance
  ... accumulators-tests-droppable
  ... accumulators-tests-error_of
  ... accumulators-tests-extended_p_square
  ... accumulators-tests-extended_p_square_quantile

Note that they are prefixed with the name of the project, a dash, and
'tests'.  Under visual studio you will see these targets in the
'solution explorer'.

.. _the_dashboard:

The Dashboard
-------------

Donated by kitware, it is here:

http://www.cdash.org/CDashPublic/index.php?project=Boost

Submitting Results
------------------

.. warning:: This needs updating for git

The ``ctest`` command can be used by individual developers to test
local changes to their libraries. The same program can also be used to
build all of Boost, run its regression tests, and submit the results
to a central server where others can view them. Currently, regression
test results based on the CMake build system are displayed on the Dart
server at http://www.cdash.org/CDashPublic/index.php?project=Boost.

To submit "experimental" results to the Dart server, configure a Boost
binary tree by following the configuration instructions in the section
:ref:`quickstart`, and then enable regression testing via the
`BOOST_TESTS=ALL` option, as described above. At this point, don't build
anything! We'll let CTest do that work. You may want to customize some
of the advanced CMake options, such as `SITE` (to give your site
name), and `MAKECOMMAND` (which, for makefile targets, governs the
top-level make call when building Boost). Finally, go into the Boost
binary directory and execute::

  ctest -D Experimental

CTest will then reconfigure Boost, build all of the Boost libraries
and regression tests, execute the regression tests, and submit the
results to the Dart dashboard at
http://www.cdash.org/CDashPublic/index.php?project=Boost.  Results
submitted to the dashboard are usually browsable momentarily within a
minute or two.

Automatic testing
-----------------

Continuous 
^^^^^^^^^^

Here is a recommended setup.

Create a directory ``ctest`` on your test drone containing
subdirectories for the branches you'll be testing, in this case
*release* and *trunk*. ::

  boost/
    ctest/
      branches/
        release/
          continuous/ 
            build/        <= run ctest here
            src/          <= checkout to here
          nightly/    
            build/        <= run ctest here
            src/          <= checkout to here

and check out source to the directories listed above.  We'll do the
release branch as an example::

  % cd boost/ctest/branches/release
  % svn co http://svn.boost.org/svn/boost/branches/release src
  #
  # lots of output
  #
  % mkdir continuous
  % cd continuous

now configure your build, enabling testing.  In this case I'll also
use an alternate compiler, from Intel::

  % cmake ../src -DBUILD_TESTING=ON -DCMAKE_C_COMPILER=icc -DCMAKE_CXX_COMPILER=icpc
  -- The C compiler identification is Intel
  -- The CXX compiler identification is Intel
  -- Check for working C compiler: /opt/intel/Compiler/11.0/083/bin/intel64/icc
  -- Check for working C compiler: /opt/intel/Compiler/11.0/083/bin/intel64/icc -- works

     (etc)

  -- Configuring done
  -- Generating done
  -- Build files have been written to: /home/troy/Projects/boost/ctest/release/continuous/build

Now run ``ctest -D Continuous`` in a loop::

  % while true
  while> do
  while> ctest -D Continuous
  while> sleep 600   # take it easy on the repository
  while> done
     Site: zinc
     Build name: intel-11.0-linux
  Create new tag: 20090514-2207 - Continuous
  Start processing tests
  Updating the repository
     Updating the repository: /home/troy/Projects/boost/ctest/release/nightly/src
     Use SVN repository type
     Old revision of repository is: 53002
     New revision of repository is: 53005
     Gathering version information (one . per revision):

     (etc)

If you add ``-V or -VV`` you'll get a little more feedback about what
is going on.  On unix it is handy to do this via the utility *screen*.

.. todo:: Figure out how to do this on windows, encapsulate some of
   	  this scripting.  Just use the ctest builtin scripting
   	  language.


Nightly
^^^^^^^

Nightly testing should run triggered by a cron job or by Windows Task
Scheduler or what-have-you.  You will need,

* a directory to work in
* installed cmake/ctest/svn

but not a checkout of boost.  CTest will do the checkout, build, test
and submit on its own.

Create a directory to run in.  As in the previous section, we'll use
``boost/ctest/branches/release/nightly``, which I'll call ``$DIR``.
The CTest script should look like the following (you can copy/paste
this into ``$DIR/CTestNightly.cmake`` ::

  execute_process(COMMAND /bin/pwd
    OUTPUT_VARIABLE PWD
    OUTPUT_STRIP_TRAILING_WHITESPACE)

  message(STATUS "Running nightly build in ${PWD}")

  set(CTEST_SOURCE_DIRECTORY ${PWD}/src)
  set(CTEST_BINARY_DIRECTORY ${PWD}/build)

  # what cmake command to use for configuring this dashboard
  set(CTEST_CMAKE_COMMAND "/usr/local/bin/cmake")
  set(CTEST_CTEST_COMMAND "/usr/local/bin/ctest")
  set(CTEST_CVS_COMMAND "svn")

  set(CTEST_CVS_CHECKOUT  "${CTEST_CVS_COMMAND} co https://svn.boost.org/svn/boost/branches/release ${CTEST_SOURCE_DIRECTORY}")

  # which ctest command to use for running the dashboard
  set(CTEST_COMMAND
    "${CTEST_CTEST_COMMAND} -VV -D Experimental -A ${PWD}/notes.txt -O ctest.log"
    )



  ####################################################################
  # The values in this section are optional you can either
  # have them or leave them commented out
  ####################################################################

  # should ctest wipe the binary tree before running
  set(CTEST_START_WITH_EMPTY_BINARY_DIRECTORY TRUE)

  #
  # this is the initial cache to use for the binary tree, be careful to escape
  # any quotes inside of this string if you use it
  #
  # Yes you can pass cmake -DBUILD_WHATEVER=ON type options here.
  #
  set(CTEST_INITIAL_CACHE "

  CMAKE_CXX_COMPILER:STRING=/opt/intel/Compiler/11.0/083/bin/intel64/icpc
  CMAKE_C_COMPILER:STRING=/opt/intel/Compiler/11.0/083/bin/intel64/icc

  SITE:STRING=zinc
  MAKECOMMAND:STRING=make -i -j2
  DART_TESTING_TIMEOUT:STRING=30
  BUILD_TESTS:STRING=ALL
  BUILD_EXAMPLES:STRING=ALL
  CVSCOMMAND:FILEPATH=${CTEST_CVS_COMMAND}
  ")

You will need to customize several variables:

* **CTEST_CMAKE_COMMAND** the path to your cmake binary
* **CTEST_CTEST_COMMAND** the path to your ctest binary (should be in
  the same place as cmake)
* **CTEST_CVS_COMMAND** The path to subversion.
* **CMAKE_CXX_COMPILER:STRING**, **CMAKE_C_COMPILER:STRING** Note the
  syntax here, the trailing ``:STRING``.  If you are using a
  nonstandard compiler, set it here.
* **MAKECOMMAND:STRING** The path to your make command.  *NOTE* if you
  set this, be sure that the ``-i`` (ignore-errors) flag is included.
  If it isn't, the first compile/link error will stop the build and
  testing will commence.
* **SITE:STRING** This is what will appear as the 'hostname' in your
  posted dashboards.  Customize as you like.

Now you'll create a "notes" file, call it ``notes.txt``.  This will be
visible from the dashboard.   Add the output of, e.g::

  gcc --version
  uname -a

and the contents of the ``CTestNightly.cmake`` itself.  Example::

  **************** CMAKE DASHBOARD NOTES ***************** 
  
  Notes file for CMake Nightly Dashboard. 
  
  This dashboard is being generated on an eight core, 64 bit 
  Ubuntu 9.04 machine with an intel c++ compiler. 
  
  
  Questions about this Dashboard should be directed to troy@resophonic.com 
  
  Linux zinc 2.6.27-11-generic #1 SMP Wed Apr 1 20:53:41 UTC 2009 x86_64 GNU/Linux 
  
  icpc (ICC) 11.0 20090318
  Copyright (C) 1985-2009 Intel Corporation.  All rights reserved. 
  
  --------------- Script file ---------------
  
  (contents of CTestNightly.cmake)

Now run (as a cronjob or at the command line)::

  ctest -S CTestNightly.cmake

if you want extra verbosity add a ``-VV`` flag.  You'll see something like the following::

  + /opt/local/bin/ctest -VV -S CMakeDashBoard.cmake
  * Extra verbosity turned on
  Reading Script: /Users/troy/ctest/boost/release/nightly/CMakeDashBoard.cmake
  Run cmake command: /opt/i3/ports/bin/cmake "/Users/troy/ctest/boost/release/nightly/src"
  -- The C compiler identification is GNU
  -- The CXX compiler identification is GNU
  -- Check for working C compiler: /usr/bin/gcc
  (etc)
  -- Configuring done
  -- Generating done
  -- Build files have been written to: /Users/troy/ctest/boost/release/nightly/build
  Run ctest command: /opt/i3/ports/bin/ctest -VV -D Nightly -A /Users/troy/ctest/boost/release/nightly/notes.txt -O ctest.log
  UpdateCTestConfiguration  from :/Users/troy/ctest/boost/release/nightly/build/DartConfiguration.tcl
  Parse Config file:/Users/troy/ctest/boost/release/nightly/build/DartConfiguration.tcl
     Site: silver
     Build name: gcc-4.0.1-macos
  (etc, etc)

You'll see it configure again, run... and sooner or later you'll see
your results on :ref:`the_dashboard`.
