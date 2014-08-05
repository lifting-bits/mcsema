.. index:: zlib, external dependency
.. _zlib:


Zlib
=====

If ``WITH_ZLIB`` is ``ON``, Zlib is detected via the standard cmake
``find_package(Zlib)``.  The following variables are set:

+----------------------+----------------------------------------+
|``ZLIB_FOUND``        |Zlib was found                          |
+----------------------+----------------------------------------+
|``ZLIB_INCLUDE_DIR``  |Path to Zlib includes                   |
+----------------------+----------------------------------------+
|``ZLIB_LIBRARIES``    |Libraries to link to when using Zlib    |
+----------------------+----------------------------------------+
