..
.. Copyright (C) 2009 Troy Straszheim <troy@resophonic.com>
..
.. Distributed under the Boost Software License, Version 1.0. 
.. See accompanying file LICENSE_1_0.txt or copy at 
..   http://www.boost.org/LICENSE_1_0.txt 
..

.. _faq:

FAQ
===

A collection of asked questions.


How do I set ``/D _SECURE_SCL=0`` on the commandline for release builds?
------------------------------------------------------------------------

* Run the cmake gui, pick the source and build directories, click
  *Configure*

* Find the entry called ``RELEASE_COMPILE_FLAGS`` and modify to taste.
  (See also :ref:`per_feature_flags`)

* Click *Configure* again, settings will be regenerated with your
  flags intact.

* Click *Generate*

* Run Visual Studio, navigate to the build directory, open
  ``Boost.sln``, build, profit.

Note:   I couldn't find the magic checkbox to tell visual studio show me
what commands it executes while building.   I switched the cmake gui to
'advanced mode' and change CMAKE_VERBOSE_MAKEFILES to TRUE.  Is there a
more 'visualstudioesque' way to do this?

-t



