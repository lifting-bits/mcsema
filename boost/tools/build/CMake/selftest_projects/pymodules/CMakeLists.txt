#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#

if (NOT PYTHON_FOUND)
  message(STATUS "+-- python not found, disabling.")
else()

  boost_library_project(
    pymodules
    SRCDIRS   src
    )

endif()
