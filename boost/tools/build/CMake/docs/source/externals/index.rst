.. index:: External Dependencies; selectively disabling

.. _external_dependencies:

External Dependencies
=====================

Each external dependency has an associated option ``WITH_``\
*dependency* that controls whether detection of the dependency will
happen at all.  These options default to ``ON``.  

Each external will set a variable *external*\ ``_FOUND`` if detection
was successful.  If this variable is empty (or ``FALSE``, 0, or
``NO``) detection will be reattempted each time you configure.

To **disable** the detection of any given external dependency and
thereby any libraries or features that depend on it, set option
``WITH_``\ *dependency* to ``NO`` (or ``OFF``, etc.)::

  % cmake ../src -DWITH_PYTHON=OFF
  -- The C compiler identification is GNU
  -- The CXX compiler identification is GNU
  ... more output ...
  -- 
  -- Python:
  -- Disabled since WITH_PYTHON=OFF
  -- 
  ... more output ...
  -- + python
  -- +-- disabled since PYTHON_FOUND is false
  -- 

.. toctree::
   :maxdepth: 3

   bzip2
   doxygen
   expat
   icu
   mpi
   python
   xsltproc
   valgrind
   zlib
