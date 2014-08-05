.. index:: Valgrind, external dependency
.. _Valgrind:


Valgrind
========

Boost.cmake does a standard path search for ``valgrind``.  If found, 
it sets the following variables


+----------------------------------------+----------------------------------------+
|``VALGRIND_FOUND``                      |Was valgrind found                      |
+----------------------------------------+----------------------------------------+
|``VALGRIND_FLAGS``                      |"--tool=memcheck"                       |
+----------------------------------------+----------------------------------------+
|``VALGRIND_EXECUTABLE``                 |path to the executable                  |
+----------------------------------------+----------------------------------------+

.. index:: WITH_VALGRIND

If the setting ``WITH_VALGRIND`` is ``ON``, (see
:ref:`external_dependencies`) then tests will be run under valgrind.
Tip: CTest's ``-V`` flag will show you the exact commands run and
output of each test.


