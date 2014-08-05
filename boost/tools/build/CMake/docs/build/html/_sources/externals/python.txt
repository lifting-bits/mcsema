.. index:: Python
.. _python_external:

========
 Python
========

By default, Boost.CMake will use the python detection built in to
cmake.  The relevant variables (command line or environment) are:

.. index:: PYTHON_EXECUTABLE
.. _python_executable:

PYTHON_EXECUTABLE
-----------------

The path to the python executable, e.g. ``/usr/local/Python-3.1.1/bin/python3``

.. index:: PYTHON_DEBUG_LIBRARIES
.. _python_debug_libraries:

PYTHON_DEBUG_LIBRARIES
----------------------

The path to the python debug library,  typically only used by developers.

.. index:: PYTHON_LIBRARIES
.. _python_libraries:

PYTHON_LIBRARIES
----------------

The path to the python library,
e.g. ``/usr/local/Python-3.1.1/lib/libpython3.1.so``

.. index:: PYTHON_INCLUDE_PATH
.. index:: Python.h
.. _python_include_path:

PYTHON_INCLUDE_PATH
-------------------

The path to the include directory,
e.g. ``/usr/local/Python-3.1.1/include/python3.1``.  Note that cmake
will check for the file ``Python.h`` in this directory and complain if
it is not found.

There are two ways to specify these, on the command line or via
environment variables.  Environment variables will override command
line flags if present.
 
.. rubric:: Command line

::

  % cmake ../src -DPYTHON_EXECUTABLE=/path/to/bin/python3          \
                 -DPYTHON_LIBRARIES=/path/to/libpython3.1.so       \
                 -DPYTHON_INCLUDE_PATH=/path/to/include/python3.1

.. rubric:: Exported environment variables

::

  % export PYTHON_EXECUTABLE=/path/to/bin/python
  % export PYTHON_LIBRARIES=/path/to/libpython3.1.so
  % export PYTHON_INCLUDE_PATH=/path/to/include/python3.1
  % cmake ../src

Either way, in the configuration output, you should see something
like::

  -- Testing PYTHON_EXECUTABLE from environment
  -- Ok, using /path/to/bin/python3
  -- Testing PYTHON_LIBRARIES from environment
  -- Ok, using /path/to/lib/libpython3.1.so.
  -- Skipping optional PYTHON_DEBUG_LIBRARIES:  not set.
  -- Testing PYTHON_INCLUDE_PATH from environment
  -- Ok, using /path/to/include/python3.1
  -- Python:
  --   executable:   /path/to/bin/python3
  --   lib:          /path/to/lib/libpython3.1.so
  --   debug lib:    
  --   include path: /path/to/include/python3.1
  
**NOTE**, once successfully detected, the python configuration will
not be redetected.  To modify, edit the relevant entries in your
CMakeCache.txt, or delete it entirely to trigger redetection.

