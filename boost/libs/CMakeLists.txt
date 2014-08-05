#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
# Find each subdirectory containing a CMakeLists.txt file, and include
# it. This avoids the need to manually list which libraries in Boost
# have CMakeLists.txt files.

# return a list of directories that we should add_subdirectory()
macro(BOOST_COLLECT_SUBPROJECT_DIRECTORY_NAMES dirname varname filename)
  file(GLOB globbed RELATIVE "${dirname}" "${dirname}/*/${filename}")
  foreach(file ${globbed})
    get_filename_component(dir ${file} PATH)
    set(${varname} ${${varname}} ${dir})
  endforeach()
endmacro()

# Find all of the subdirectories with .cmake files in them. These are
# the libraries with dependencies.
boost_collect_subproject_directory_names(${BOOST_LIBS_PARENT_DIR} BOOST_MODULE_DIRS "module.cmake")
foreach(subdir ${BOOST_MODULE_DIRS})
  include("${BOOST_LIBS_PARENT_DIR}/${subdir}/module.cmake")
endforeach(subdir)

# Find all of the subdirectories with CMakeLists.txt files in
# them. This contains all of the Boost libraries.
boost_collect_subproject_directory_names(${BOOST_LIBS_PARENT_DIR} BOOST_SUBPROJECT_DIRS "CMakeLists.txt")

# Add all of the Boost projects in reverse topological order, so that
# a library's dependencies show up before the library itself.
set(CPACK_INSTALL_CMAKE_COMPONENTS_ALL)
list(SORT BOOST_SUBPROJECT_DIRS)
topological_sort(BOOST_SUBPROJECT_DIRS BOOST_ _DEPENDS)

#
# Sanity-check for typos: all projects in BUILD_PROJECTS must exist
#
if ((NOT BUILD_PROJECTS STREQUAL "ALL") AND (NOT BUILD_PROJECTS STREQUAL "NONE"))
  foreach(project ${BUILD_PROJECTS})
    list(FIND BOOST_SUBPROJECT_DIRS ${project} THIS_SUBPROJECT_DIRS_INDEX)
    if (THIS_SUBPROJECT_DIRS_INDEX LESS 0)
      message(FATAL_ERROR "Nonexistant project \"${project}\" specified in BUILD_PROJECTS.  These project names should be all lowercase.")
    endif()
  endforeach()
endif()

set(BOOST_TEST_PROJECTS "" CACHE INTERNAL "hi" FORCE)

#
# include only directories of projects in BUILD_PROJECTS
#
message(STATUS "")
colormsg(_HIBLUE_ "Reading boost project directories (per BUILD_PROJECTS)")
message(STATUS "")
set(BOOST_ALL_COMPONENTS "")

foreach(subdir ${BOOST_SUBPROJECT_DIRS})
  list(FIND BUILD_PROJECTS ${subdir} THIS_BUILD_PROJECTS_INDEX)
  if ((THIS_BUILD_PROJECTS_INDEX GREATER -1) OR (BUILD_PROJECTS STREQUAL "ALL"))
    message(STATUS "+ ${subdir}")
    add_subdirectory(${BOOST_LIBS_PARENT_DIR}/${subdir} ${CMAKE_BINARY_DIR}/libs/${subdir})
  endif()
endforeach()

#
#  If we're doing selftests, add those selftest dirs
#
foreach(project 
    ${BOOST_CMAKE_SELFTEST_PROJECTS})
  colormsg(RED "* ${project}")
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../tools/build/CMake/selftest_projects/${project}
    ${CMAKE_BINARY_DIR}/libs/${project})
endforeach()


set(BOOST_ALL_COMPONENTS ${BOOST_ALL_COMPONENTS} PARENT_SCOPE)

if(BUILD_TESTS AND NOT BUILD_TESTS STREQUAL "NONE")
  message(STATUS "")
  colormsg(_HIBLUE_ "Traversing project test directories (per BUILD_TESTS)")
  message(STATUS "")
else()
  message(STATUS "")
  colormsg(HIGRAY "BUILD_TESTS is NONE: skipping test directories.")
  message(STATUS "")
endif()

foreach(PROJ ${BOOST_TEST_PROJECTS})
  string(TOLOWER ${PROJ} proj)
  project(${proj})
  set(BOOST_PROJECT_NAME ${proj})
  foreach(dir ${BOOST_${PROJ}_TESTDIRS})
    message(STATUS "+ ${proj}")
    add_subdirectory(${dir} ${CMAKE_BINARY_DIR}/libs/${proj}/test)
  endforeach()
endforeach()

# Write out a GraphViz file containing inter-library dependencies. 
set(BOOST_DEPENDENCY_GRAPHVIZ_FILE "${Boost_BINARY_DIR}/dependencies.dot")
file(WRITE ${BOOST_DEPENDENCY_GRAPHVIZ_FILE} "digraph boost {\n")
foreach(SUBDIR ${BOOST_SUBPROJECT_DIRS})
  string(TOUPPER "BOOST_${SUBDIR}_COMPILED_LIB" BOOST_COMPILED_LIB_VAR)
  if (${BOOST_COMPILED_LIB_VAR})
    file(APPEND ${BOOST_DEPENDENCY_GRAPHVIZ_FILE} "  \"${SUBDIR}\" [style=\"filled\" fillcolor=\"#A3A27C\" shape=\"box\"];\n ")
  endif (${BOOST_COMPILED_LIB_VAR})
  string(TOUPPER "BOOST_${SUBDIR}_DEPENDS" DEPENDS_VAR)
  if(DEFINED ${DEPENDS_VAR})
    foreach(DEP ${${DEPENDS_VAR}})
      file(APPEND ${BOOST_DEPENDENCY_GRAPHVIZ_FILE} 
        "  \"${SUBDIR}\" -> \"${DEP}\";\n")
    endforeach()
  endif()
endforeach()
file(APPEND ${BOOST_DEPENDENCY_GRAPHVIZ_FILE} "  \"test\" [style=\"filled\" fillcolor=\"#A3A27C\" shape=\"box\"];\n ")
file(APPEND ${BOOST_DEPENDENCY_GRAPHVIZ_FILE} "}\n")
