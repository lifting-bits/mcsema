#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
# Add a library target to the build system
boost_library_project(
  flyweight
  TESTDIRS  test
  HEADERS flyweight flyweight.hpp
  #  DOCDIRS 
  DESCRIPTION  "Flyweights are small-sized handle classes granting constant access to shared common data, thus allowing for the management of large amounts of entities within reasonable memory limits. Boost.Flyweight makes it easy to use this common programming idiom by providing the class template flyweight<T>, which acts as a drop-in replacement for const T."
  MODULARIZED
  AUTHORS  "Joaquín M López Muñoz <fixme -at- fixme.com>"
)


