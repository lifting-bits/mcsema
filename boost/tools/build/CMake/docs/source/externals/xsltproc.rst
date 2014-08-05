.. index:: Xsltproc, external dependency
.. _Xsltproc:


Xsltproc
========

Boost.cmake does a standard path search for ``xsltproc``.  If found, 
it sets the following variables


+----------------------------------------+----------------------------------------+
|``XSLTPROC_FOUND``                      |Was xsltproc found                      |
+----------------------------------------+----------------------------------------+
|``XSLTPROC_FLAGS``                      |"--xinclude"                            |
+----------------------------------------+----------------------------------------+
|``XSLTPROC_EXECUTABLE``                 |path to the executable                  |
+----------------------------------------+----------------------------------------+
