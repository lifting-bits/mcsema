.. index:: bzip2, external dependency
.. _bzip2:


BZip2
=====

If ``WITH_BZIP2`` is ``ON``, BZip2 is detected via the standard cmake
``find_package(BZip2)``.  The following variables are set:

+----------------------+----------------------------------------+
|``BZIP2_FOUND``       |Bzip2 was found                         |
+----------------------+----------------------------------------+
|``BZIP2_INCLUDE_DIR`` |Path to BZip2 includes                  |
+----------------------+----------------------------------------+
|``BZIP2_DEFINITIONS`` |Compile line flags for BZip2            |
+----------------------+----------------------------------------+
|``BZIP2_LIBRARIES``   |Libraries to link to when using BZip2   |
+----------------------+----------------------------------------+
