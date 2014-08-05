##########################################################################
# Core Functionality for Boost                                           #
##########################################################################
# Copyright (C) 2007-2009 Douglas Gregor <doug.gregor@gmail.com>         #
# Copyright (C) 2007-2009 Troy Straszheim <troy@resophonic.com>          #
#                                                                        #
# Distributed under the Boost Software License, Version 1.0.             #
# See accompanying file LICENSE_1_0.txt or copy at                       #
#   http://www.boost.org/LICENSE_1_0.txt                                 #
##########################################################################
# Important developer macros in this file:                               #
#                                                                        #
#   boost_library_project: Defines a Boost library project (e.g.,        #
#   Boost.Python).                                                       #
#                                                                        #
#   boost_add_library: Builds library binaries for Boost libraries       #
#   with compiled sources (e.g., boost_filesystem).                      #
#                                                                        #
#   boost_add_executable: Builds executables.                            #
##########################################################################

# Defines a Boost library project (e.g., for Boost.Python). Use as:
#
#   boost_library_project(libname
#                         [SRCDIRS srcdir1 srcdir2 ...] 
#                         [TESTDIRS testdir1 testdir2 ...]
#                         [DEPENDS lib1 lib2 ...]
#                         [DESCRIPTION description]
#                         [AUTHORS author1 author2 ...]
#                         [MAINTAINERS maint1 maint2 ...]
#                         [MODULARIZED])
#
# where libname is the name of the library (e.g., Python, or
# Filesystem), srcdir1, srcdir2, etc, are subdirectories containing
# library sources (for Boost libraries that build actual library
# binaries), and testdir1, testdir2, etc, are subdirectories
# containing regression tests. DEPENDS lists the names of the other
# Boost libraries that this library depends on. If the dependencies
# are not satisfied (e.g., because the library isn't present or its
# build is turned off), this library won't be built. 
#
# DESCRIPTION provides a brief description of the library, which can
# be used to summarize the behavior of the library for a user. AUTHORS
# lists the authors of the library, while MAINTAINERS lists the active
# maintainers. If MAINTAINERS is left empty, it is assumed that the 
# authors are still maintaining the library. Both authors and maintainers
# should have their name followed by their current e-mail address in
# angle brackets, with -at- instead of the at sign, e.g.,
#   Douglas Gregor <doug.gregor -at- gmail.com>
#
# Example: 
#   boost_library_project(
#     Thread
#     SRCDIRS src 
#     TESTDIRS test
#     )
macro(boost_library_project LIBNAME)
  parse_arguments(THIS_PROJECT
    "SRCDIRS;TESTDIRS;EXAMPLEDIRS;HEADERS;DOCDIRS;DESCRIPTION;AUTHORS;MAINTAINERS"
    "MODULARIZED"
    ${ARGN}
    )

  # Set THIS_PROJECT_DEPENDS_ALL to the set of all of its
  # dependencies, its dependencies' dependencies, etc., transitively.
  string(TOUPPER "BOOST_${LIBNAME}_DEPENDS" THIS_PROJECT_DEPENDS)
  set(THIS_PROJECT_DEPENDS_ALL ${${THIS_PROJECT_DEPENDS}})
  set(ADDED_DEPS TRUE)
  while (ADDED_DEPS)
    set(ADDED_DEPS FALSE)
    foreach(DEP ${THIS_PROJECT_DEPENDS_ALL})
      string(TOUPPER "BOOST_${DEP}_DEPENDS" DEP_DEPENDS)
      foreach(DEPDEP ${${DEP_DEPENDS}})
        list(FIND THIS_PROJECT_DEPENDS_ALL ${DEPDEP} DEPDEP_INDEX)
        if (DEPDEP_INDEX EQUAL -1)
          list(APPEND THIS_PROJECT_DEPENDS_ALL ${DEPDEP})
          set(ADDED_DEPS TRUE)
        endif()
      endforeach()
    endforeach()
  endwhile()

  string(TOLOWER "${LIBNAME}" libname)
  string(TOLOWER "${LIBNAME}" BOOST_PROJECT_NAME)
  string(TOUPPER "${LIBNAME}" ULIBNAME)
  project(${LIBNAME})
  

  if (THIS_PROJECT_MODULARIZED OR THIS_PROJECT_SRCDIRS)
    
    # We only build a component group for modularized libraries or libraries
    # that have compiled parts.
    if (COMMAND cpack_add_component_group)
      # Compute a reasonable description for this library.
      if (THIS_PROJECT_DESCRIPTION)
        set(THIS_PROJECT_DESCRIPTION "Boost.${LIBNAME}\n\n${THIS_PROJECT_DESCRIPTION}")
        
        if (THIS_PROJECT_AUTHORS)
          list(LENGTH THIS_PROJECT_AUTHORS THIS_PROJECT_NUM_AUTHORS)
          if (THIS_PROJECT_NUM_AUTHORS EQUAL 1)
            set(THIS_PROJECT_DESCRIPTION "${THIS_PROJECT_DESCRIPTION}\n\nAuthor: ")
          else()
            set(THIS_PROJECT_DESCRIPTION "${THIS_PROJECT_DESCRIPTION}\n\nAuthors: ")
          endif()
          set(THIS_PROJECT_FIRST_AUTHOR TRUE)
          foreach(AUTHOR ${THIS_PROJECT_AUTHORS})
            string(REGEX REPLACE " *-at- *" "@" AUTHOR ${AUTHOR})
            if (THIS_PROJECT_FIRST_AUTHOR)
              set(THIS_PROJECT_FIRST_AUTHOR FALSE)
            else()
              set(THIS_PROJECT_DESCRIPTION "${THIS_PROJECT_DESCRIPTION}\n         ")
            endif()
            set(THIS_PROJECT_DESCRIPTION "${THIS_PROJECT_DESCRIPTION}${AUTHOR}")
          endforeach(AUTHOR)
        endif (THIS_PROJECT_AUTHORS)

        if (THIS_PROJECT_MAINTAINERS)
          list(LENGTH THIS_PROJECT_MAINTAINERS THIS_PROJECT_NUM_MAINTAINERS)
          if (THIS_PROJECT_NUM_MAINTAINERS EQUAL 1)
            set(THIS_PROJECT_DESCRIPTION "${THIS_PROJECT_DESCRIPTION}\nMaintainer: ")
          else()
            set(THIS_PROJECT_DESCRIPTION "${THIS_PROJECT_DESCRIPTION}\nMaintainers: ")
          endif()
          set(THIS_PROJECT_FIRST_MAINTAINER TRUE)
          foreach(MAINTAINER ${THIS_PROJECT_MAINTAINERS})
            string(REGEX REPLACE " *-at- *" "@" MAINTAINER ${MAINTAINER})
            if (THIS_PROJECT_FIRST_MAINTAINER)
              set(THIS_PROJECT_FIRST_MAINTAINER FALSE)
            else()
              set(THIS_PROJECT_DESCRIPTION "${THIS_PROJECT_DESCRIPTION}\n             ")
            endif()
            set(THIS_PROJECT_DESCRIPTION "${THIS_PROJECT_DESCRIPTION}${MAINTAINER}")
          endforeach(MAINTAINER)
        endif (THIS_PROJECT_MAINTAINERS)
      endif (THIS_PROJECT_DESCRIPTION)
      
      # Create a component group for this library
      fix_cpack_component_name(CPACK_COMPONENT_GROUP_NAME ${libname})
      cpack_add_component_group(${CPACK_COMPONENT_GROUP_NAME}
        DISPLAY_NAME "${LIBNAME}"
        DESCRIPTION ${THIS_PROJECT_DESCRIPTION})
    endif () # COMMAND cpake_add_component_group
  endif () # THIS_PROJECT_MODULARIZED OR THIS_PROJECT_SRCDIRS
  
  if (THIS_PROJECT_MODULARIZED)
    #
    # Don't add this module's include directory
    # until modularization makes sense
    #
    # include_directories("${Boost_SOURCE_DIR}/libs/${libname}/include")
    
    #
    # Horrible hackery.  Make install of headers from modularized directories
    # OPTIONAL, which only works on cmake >= 2.7
    # 
    #
    # TDS 20091009: disable this modularized stuff, as forcing
    # people to make modularize (which wastes your source directory)
    # is a huge hassle and anyway it looks like the 'modularization'
    # of boost is dead for a while.
    #

    # if (${CMAKE_MAJOR_VERSION} GREATER 1 AND ${CMAKE_MINOR_VERSION} GREATER 6)
    # 	# Install this module's headers
    # 	install(DIRECTORY include/boost 
    #     DESTINATION ${BOOST_HEADER_DIR}
    # 	  ${_INSTALL_OPTIONAL}
    #     COMPONENT ${libname}_headers
    #     PATTERN "CVS" EXCLUDE
    #     PATTERN ".svn" EXCLUDE)
    # else()
    # 	if (EXISTS include/boost)
    # 	  # Install this module's headers
    # 	  install(DIRECTORY include/boost 
    #       DESTINATION ${BOOST_HEADER_DIR}
    # 	    ${_INSTALL_OPTIONAL}
    #       COMPONENT ${libname}_headers
    #       PATTERN "CVS" EXCLUDE
    #       PATTERN ".svn" EXCLUDE)
    # 	endif()
    # endif()

    
    if (COMMAND cpack_add_component)        
      # Determine the header dependencies
      set(THIS_PROJECT_HEADER_DEPENDS)
      foreach(DEP ${${THIS_PROJECT_DEPENDS}})
        string(TOLOWER ${DEP} dep)
        if (${dep} STREQUAL "serialization")
          # TODO: Ugly, ugly hack until the serialization library is modularized
        elseif (${dep} STREQUAL "thread")
        else()
          list(APPEND THIS_PROJECT_HEADER_DEPENDS ${dep}_headers)
        endif()
      endforeach(DEP)

      # Tell CPack about the headers component
      fix_cpack_component_name(CPACK_COMPONENT_GROUP_NAME ${libname})
      cpack_add_component(${libname}_headers
        DISPLAY_NAME "Header files"
        GROUP      ${CPACK_COMPONENT_GROUP_NAME}
        DEPENDS    ${THIS_PROJECT_HEADER_DEPENDS})
    endif ()
  endif () # THIS_PROJECT_MODULARIZED

  #-- This is here to debug the modularize code
  set(modularize_debug FALSE)
  if (modularize_debug)
    set(modularize_output ${Boost_BINARY_DIR})
    set(modularize_libs_dir "modularize")
  else (modularize_debug)
    set(modularize_output ${Boost_SOURCE_DIR})
    set(modularize_libs_dir "libs")
  endif(modularize_debug)

  #
  # Modularization code
  #
  if(THIS_PROJECT_HEADERS)
    set(${LIBNAME}-modularize-commands)
    foreach(item ${THIS_PROJECT_HEADERS})
      if(EXISTS "${Boost_SOURCE_DIR}/boost/${item}")
        if(IS_DIRECTORY "${Boost_SOURCE_DIR}/boost/${item}")
          list(APPEND ${LIBNAME}-modularize-commands
            COMMAND "${CMAKE_COMMAND}" -E copy_directory
            "${Boost_SOURCE_DIR}/boost/${item}"
            "${modularize_output}/${modularize_libs_dir}/${libname}/include/boost/${item}"
            )
          if (NOT modularize_debug)
            list(APPEND ${LIBNAME}-modularize-commands
              COMMAND "${CMAKE_COMMAND}" -E remove_directory "${Boost_SOURCE_DIR}/boost/${item}" 
              )
          endif (NOT modularize_debug)
        else(IS_DIRECTORY "${Boost_SOURCE_DIR}/boost/${item}")
          list(APPEND ${LIBNAME}-modularize-commands
            COMMAND "${CMAKE_COMMAND}" -E copy
            "${Boost_SOURCE_DIR}/boost/${item}"
            "${modularize_output}/${modularize_libs_dir}/${libname}/include/boost/${item}"
            )
          if (NOT modularize_debug)
            list(APPEND ${LIBNAME}-modularize-commands
              COMMAND "${CMAKE_COMMAND}" -E remove "${Boost_SOURCE_DIR}/boost/${item}" 
              )
          endif (NOT modularize_debug)
          
        endif(IS_DIRECTORY "${Boost_SOURCE_DIR}/boost/${item}")
      elseif(EXISTS "${Boost_SOURCE_DIR}/${modularize_libs_dir}/${libname}/include/boost/${item}")
        # Okay; already modularized
      else()
        message(SEND_ERROR 
          "Header or directory boost/${item} does not exist. The HEADERS argument in ${Boost_SOURCE_DIR}/${modularize_libs_dir}/${libname}/CMakeLists.txt should be updated.")
      endif()
    endforeach(item)

    if (${LIBNAME}-modularize-commands)
      set(${LIBNAME}-modularize-commands
        # COMMAND "${CMAKE_COMMAND}" -E remove_directory "${modularize_output}/libs/${libname}/include"
        COMMAND "${CMAKE_COMMAND}" -E make_directory
        "${modularize_output}/${modularize_libs_dir}/${libname}/include/boost"
        ${${LIBNAME}-modularize-commands}
        )
      if (NOT modularize_debug)
        set(${LIBNAME}-modularize-commands
          COMMAND "${CMAKE_COMMAND}" -E remove_directory "${modularize_output}/${modularize_libs_dir}/${libname}/include"
          ${${LIBNAME}-modularize-commands}
          )
      endif (NOT modularize_debug)
      # disable modularization
      # add_custom_target(${LIBNAME}-modularize
      # ${${LIBNAME}-modularize-commands}
      # COMMENT "Modularizing ${LIBNAME} headers to project-local dir from monolithic boost dir"
      # )

      if(THIS_PROJECT_MODULARIZED)
        #
	# Temporarily disable modularization 
	#
	# add_dependencies(modularize ${LIBNAME}-modularize)
	#
      endif(THIS_PROJECT_MODULARIZED)
    endif()
  endif(THIS_PROJECT_HEADERS)
  
  # For each of the modular libraries on which this project depends,
  # add the include path for that library.
  set(THIS_PROJECT_HAS_HEADER_DEPENDS FALSE)
  # Temporarily disable modularization stuff.
  # foreach(DEP ${THIS_PROJECT_DEPENDS_ALL})
  #   include_directories("${modularize_output}/${modularize_libs_dir}/${DEP}/include")
  # endforeach(DEP)

  # TODO: is this still necessary?
  if(NOT EXISTS ${CMAKE_BINARY_DIR}/bin/tests)
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bin/tests)
  endif(NOT EXISTS ${CMAKE_BINARY_DIR}/bin/tests)
  if(NOT EXISTS ${CMAKE_BINARY_DIR}/bin/tests/${BOOST_PROJECT_NAME})
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bin/tests/${BOOST_PROJECT_NAME})
  endif(NOT EXISTS ${CMAKE_BINARY_DIR}/bin/tests/${BOOST_PROJECT_NAME})

  # Include each of the source directories
  if(THIS_PROJECT_SRCDIRS)
    foreach(SUBDIR ${THIS_PROJECT_SRCDIRS})
      add_subdirectory(${SUBDIR})
    endforeach(SUBDIR ${THIS_PROJECT_SRCDIRS})
  endif()

  set(BOOST_ALL_COMPONENTS ${BOOST_ALL_COMPONENTS} PARENT_SCOPE)

  #set(BOOST_${LIBNAME}_COMPONENTS ${THIS_PROJECT_COMPONENTS} PARENT_SCOPE)
  #message("BOOST_${LIBNAME}_COMPONENTS ${THIS_PROJECT_COMPONENTS}")
  #set(BOOST_ALL_COMPONENTS ${LIBNAME} ${BOOST_ALL_COMPONENTS} PARENT_SCOPE)

  list(FIND BUILD_TESTS ${libname} BUILD_TESTS_INDEX)
  if ((BUILD_TESTS_INDEX GREATER -1) OR (BUILD_TESTS STREQUAL "ALL"))
    # set the tests directories list for later inclusion
    # project(${libname}-tests)
    if (THIS_PROJECT_TESTDIRS)
      set(BOOST_TEST_PROJECTS ${ULIBNAME} ${BOOST_TEST_PROJECTS} PARENT_SCOPE)
    endif()
    foreach(SUBDIR ${THIS_PROJECT_TESTDIRS})
      # message(STATUS "+-- ${SUBDIR}")
      # add_subdirectory(${SUBDIR})
      set(BOOST_${ULIBNAME}_TESTDIRS
	${BOOST_${ULIBNAME}_TESTDIRS}
	${CMAKE_CURRENT_SOURCE_DIR}/${SUBDIR}
	PARENT_SCOPE)
    endforeach()
  endif()

  list(FIND BUILD_EXAMPLES ${libname} BUILD_EXAMPLES_INDEX)
  if ((BUILD_EXAMPLES_INDEX GREATER -1) OR (BUILD_EXAMPLES STREQUAL "ALL"))
    project(${libname}-examples)
    # Include the example directories.
    foreach(SUBDIR ${THIS_PROJECT_EXAMPLEDIRS})
      message(STATUS "+-- ${SUBDIR}")
      add_subdirectory(${SUBDIR})
    endforeach()
  endif()

  if (BUILD_DOCUMENTATION AND THIS_PROJECT_DOCDIRS)
    foreach(SUBDIR ${THIS_PROJECT_DOCDIRS})
      add_subdirectory(${SUBDIR})
    endforeach(SUBDIR)
  endif ()
endmacro(boost_library_project)

macro(boost_tool_project TOOLNAME)
  parse_arguments(THIS_PROJECT
    "DESCRIPTION;AUTHORS;MAINTAINERS"
    ""
    ${ARGN}
    )

  set(THIS_PROJECT_IS_TOOL TRUE)

  string(TOUPPER ${TOOLNAME} UTOOLNAME)
  project(${TOOLNAME})

  include_directories(${CMAKE_CURRENT_SOURCE_DIR})

  set(THIS_PROJECT_OKAY ON)
  set(THIS_PROJECT_FAILED_DEPS "")

  #   message(">>> ${BOOST_${UTOOLNAME}_DEPENDS}")
  #   foreach(DEP ${BOOST_${UTOOLNAME}_DEPENDS})
  #     get_target_property(dep_location boost_${DEP} TYPE)
  #     message("${DEP} TYPE=${dep_location}")
  #     if (NOT ${dep_location})
  #       set(THIS_PROJECT_OKAY OFF)
  #       set(THIS_PROJECT_FAILED_DEPS "${THIS_PROJECT_FAILED_DEPS}  ${DEP}\n")
  #     endif (NOT ${dep_location})
  #   endforeach(DEP)
  # 
  #   if (NOT THIS_PROJECT_OKAY)
  #     #if (BUILD_${UTOOLNAME})
  #       # The user explicitly turned on this tool in a prior
  #       # iteration, but it can no longer be built because one of the
  #       # dependencies was turned off. Force this option off and
  #       # complain about it.
  #       set(BUILD_${UTOOLNAME} OFF CACHE BOOL "Build ${TOOLNAME}" FORCE)
  #       message(SEND_ERROR "Cannot build ${TOOLNAME} due to missing library dependencies:\n${THIS_PROJECT_FAILED_DEPS}")
  #     #endif ()
  #   endif (NOT THIS_PROJECT_OKAY)
  # 
  #   if(BUILD_${UTOOLNAME} AND THIS_PROJECT_OKAY)
  #     string(TOLOWER "${TOOLNAME}" toolname)
  #     
  #     # Add this module's include directory
  # 
  #     # For each of the modular libraries on which this project depends,
  #     # add the include path for that library.
  #     foreach(DEP ${BOOST_${UTOOLNAME}_DEPENDS})
  #       string(TOUPPER ${DEP} UDEP)
  #       #
  #       # Modularization disabled
  #       #
  #       # include_directories("${Boost_SOURCE_DIR}/libs/${DEP}/include")
  #       #
  #     endforeach(DEP)
  #   endif()
endmacro(boost_tool_project)

#TODO: Finish this documentation
# Defines dependencies of a boost project and testing targets. Use as:
#
#   boost_module(libname
#                DEPENDS srcdir1 srcdir2 ...
#                TEST_DEPENDS testdir1 testdir2 ...
#
# Example: 
#   boost_library_project(
#     Thread
#     SRCDIRS src 
#     TESTDIRS test
#     )
#
macro(boost_module LIBNAME)
  parse_arguments(THIS_MODULE
    "DEPENDS"
    ""
    ${ARGN}
    )

  # Export BOOST_${LIBNAME}_DEPENDS
  string(TOUPPER "BOOST_${LIBNAME}_DEPENDS" THIS_MODULE_LIBNAME_DEPENDS)
  set(${THIS_MODULE_LIBNAME_DEPENDS} ${THIS_MODULE_DEPENDS})

  # message(STATUS "----------------------------------------------------------------")
  # message(STATUS "LIBNAME: ${LIBNAME}")
  # message(STATUS "THIS_MODULE_DEPENDS: ${THIS_MODULE_DEPENDS}")
  # message(STATUS "THIS_MODULE_LIBNAME_DEPENDS: ${THIS_MODULE_LIBNAME_DEPENDS}")
  # message(STATUS "${THIS_MODULE_LIBNAME_DEPENDS}: ${${THIS_MODULE_LIBNAME_DEPENDS}}")
  # message(STATUS "THIS_MODULE_TEST_DEPENDS: ${THIS_MODULE_TEST_DEPENDS}")
  # message(STATUS "THIS_MODULE_LIBNAME_TEST_DEPENDS: ${THIS_MODULE_LIBNAME_TEST_DEPENDS}")
  # message(STATUS "${THIS_MODULE_LIBNAME_TEST_DEPENDS}: ${${THIS_MODULE_LIBNAME_TEST_DEPENDS}}")
endmacro(boost_module)

# This macro is an internal utility macro that builds the name of a
# particular variant of a library
#
#   boost_library_variant_target_name(feature1 feature2 ...)
#
# where feature1, feature2, etc. are the names of features to be
# included in this variant, e.g., MULTI_THREADED, DEBUG. 
#
# This macro sets three macros:
#   
#   VARIANT_TARGET_NAME: The suffix that should be appended to the
#   name of the library target to name this variant of the
#   library. For example, this might be "-mt-static" for a static,
#   multi-threaded variant. It should be used to name the CMake
#   library target, e.g., boost_signals-mt-static.
#
#   VARIANT_VERSIONED_NAME: The suffix that will be added to the name
#   of the generated library, containing information about the
#   particular version of the library and the toolset used to build
#   this library. For example, this might be "-gcc41-mt-1_34" for the
#   multi-threaded, release variant of the library in Boost 1.34.0 as
#   compiled with GCC 4.1.  If option MANGLE_LIBNAMES is OFF, this 
#   variable is set to the empty string.
#
#   VARIANT_DISPLAY_NAME: The display name that describes this
#   variant, e.g., "Debug, static, multi-threaded".
#
macro(boost_library_variant_target_name)
  set(VARIANT_TARGET_NAME "")

  # The versioned name starts with the full Boost toolset
  if(WINMANGLE_LIBNAMES)
    set(VARIANT_VERSIONED_NAME "-${BOOST_TOOLSET}")
  else(WINMANGLE_LIBNAMES)
    set(VARIANT_VERSIONED_NAME "")
  endif(WINMANGLE_LIBNAMES)

  # Add -mt for multi-threaded libraries
  list_contains(VARIANT_IS_MT MULTI_THREADED ${ARGN})
  if (VARIANT_IS_MT)
    set(VARIANT_TARGET_NAME "${VARIANT_TARGET_NAME}-mt")

    # If we're creating versioned names, tack on "-mt"
    set(VARIANT_VERSIONED_NAME "${VARIANT_VERSIONED_NAME}-mt")
  endif (VARIANT_IS_MT)

  # Add -static for static libraries, -shared for shared libraries
  list_contains(VARIANT_IS_STATIC STATIC ${ARGN})
  if (VARIANT_IS_STATIC)
    set(VARIANT_TARGET_NAME "${VARIANT_TARGET_NAME}-static")
    set(VARIANT_DISPLAY_NAME "Static")
  else (VARIANT_IS_STATIC)
    set(VARIANT_TARGET_NAME "${VARIANT_TARGET_NAME}-shared")
    set(VARIANT_DISPLAY_NAME "Shared")
  endif (VARIANT_IS_STATIC)

  # Add "multi-threaded" to the display name for multithreaded libraries.
  if (VARIANT_IS_MT)
    set(VARIANT_DISPLAY_NAME "${VARIANT_DISPLAY_NAME}, multi-threaded")
  endif ()

  # Compute the ABI tag, which depends on various kinds of options
  set(VARIANT_ABI_TAG "")

  # Linking statically to the runtime library
  list_contains(VARIANT_IS_STATIC_RUNTIME STATIC_RUNTIME ${ARGN})
  if (VARIANT_IS_STATIC_RUNTIME)  
    set(VARIANT_TARGET_NAME "${VARIANT_TARGET_NAME}-staticrt")
    set(VARIANT_ABI_TAG "${VARIANT_ABI_TAG}s")
    set(VARIANT_DISPLAY_NAME "${VARIANT_DISPLAY_NAME}, static runtime")
  endif (VARIANT_IS_STATIC_RUNTIME)
  
  # Using the debug version of the runtime library.
  # With Visual C++, this comes automatically with debug
  if (MSVC)
    list_contains(VARIANT_IS_DEBUG DEBUG ${ARGN})
    if (VARIANT_IS_DEBUG)
      set(VARIANT_ABI_TAG "${VARIANT_ABI_TAG}g")
    endif (VARIANT_IS_DEBUG)
  endif (MSVC)

  # Add -pydebug for debug builds of Python
  list_contains(VARIANT_IS_PYDEBUG PYTHON_DEBUG ${ARGN})
  if (VARIANT_IS_PYDEBUG)
    set(VARIANT_TARGET_NAME "${VARIANT_TARGET_NAME}-pydebug")
    set(VARIANT_ABI_TAG "${VARIANT_ABI_TAG}y")
    set(VARIANT_DISPLAY_NAME "${VARIANT_DISPLAY_NAME}, Python debugging")
  endif (VARIANT_IS_PYDEBUG)

  # TODO: STLport rather than default library
  # TODO: STLport's deprecated iostreams

  # Add -debug for debug libraries
  list_contains(VARIANT_IS_DEBUG DEBUG ${ARGN})
  # message("ARGN=${ARGN}")
  if (VARIANT_IS_DEBUG)
    set(VARIANT_TARGET_NAME "${VARIANT_TARGET_NAME}-debug")

    set(VARIANT_ABI_TAG "${VARIANT_ABI_TAG}d")

    set(VARIANT_DISPLAY_NAME "${VARIANT_DISPLAY_NAME}, debug")
  else()
    set(VARIANT_DISPLAY_NAME "${VARIANT_DISPLAY_NAME}, release")
  endif()

  # If there is an ABI tag, append it to the versioned name
  if (VARIANT_ABI_TAG)
    set(VARIANT_VERSIONED_NAME "${VARIANT_VERSIONED_NAME}-${VARIANT_ABI_TAG}")
  endif (VARIANT_ABI_TAG)

  if(WINMANGLE_LIBNAMES)
    # Append the Boost version number to the versioned name
    if(BOOST_VERSION_SUBMINOR GREATER 0)
      set(VARIANT_VERSIONED_NAME
	"${VARIANT_VERSIONED_NAME}-${BOOST_VERSION_MAJOR}_${BOOST_VERSION_MINOR}_${BOOST_VERSION_SUBMINOR}")
    else(BOOST_VERSION_SUBMINOR GREATER 0)
      set(VARIANT_VERSIONED_NAME 
	"${VARIANT_VERSIONED_NAME}-${BOOST_VERSION_MAJOR}_${BOOST_VERSION_MINOR}")
    endif(BOOST_VERSION_SUBMINOR GREATER 0)
  endif(WINMANGLE_LIBNAMES)
endmacro(boost_library_variant_target_name)

# This macro is an internal utility macro that updates compilation and
# linking flags based on interactions among the features in a variant.
#
#   boost_feature_interactions(prefix
#                              feature1 feature2 ...)
#
# where "prefix" is the prefix of the compilation and linking flags
# that will be updated (e.g., ${prefix}_COMPILE_FLAGS). feature1,
# feature2, etc. are the names of the features used in this particular
# variant. If the features in this variant conflict, set
# ${prefix}_OKAY to FALSE.
macro(boost_feature_interactions PREFIX)
  # Don't build or link against a shared library and a static run-time
  list_contains(IS_SHARED SHARED ${ARGN})
  list_contains(IS_STATIC_RUNTIME STATIC_RUNTIME ${ARGN})
  if (IS_SHARED AND IS_STATIC_RUNTIME)
    set(${PREFIX}_OKAY FALSE)
  endif (IS_SHARED AND IS_STATIC_RUNTIME)
  
  # With Visual C++, the dynamic runtime is multi-threaded only
  if (MSVC)
    list_contains(IS_DYNAMIC_RUNTIME DYNAMIC_RUNTIME ${ARGN})
    list_contains(IS_SINGLE_THREADED SINGLE_THREADED ${ARGN})
    if (IS_DYNAMIC_RUNTIME AND IS_SINGLE_THREADED)
      set(${PREFIX}_OKAY FALSE)
    endif (IS_DYNAMIC_RUNTIME AND IS_SINGLE_THREADED) 
  endif (MSVC)

  # Visual C++-specific runtime library flags
  if(MSVC)
    list_contains(IS_STATIC_RUNTIME STATIC_RUNTIME ${ARGN})
    list_contains(IS_DEBUG DEBUG ${ARGN})
    if(IS_DEBUG)
      if(IS_STATIC_RUNTIME)
        set(${PREFIX}_COMPILE_FLAGS "/MTd ${${PREFIX}_COMPILE_FLAGS}")
      else(IS_STATIC_RUNTIME)
        set(${PREFIX}_COMPILE_FLAGS "/MDd ${${PREFIX}_COMPILE_FLAGS}")
      endif(IS_STATIC_RUNTIME)       
    else(IS_DEBUG)
      if(IS_STATIC_RUNTIME)
        set(${PREFIX}_COMPILE_FLAGS "/MT ${${PREFIX}_COMPILE_FLAGS}")
      else(IS_STATIC_RUNTIME)
        set(${PREFIX}_COMPILE_FLAGS "/MD ${${PREFIX}_COMPILE_FLAGS}")
      endif(IS_STATIC_RUNTIME)       
    endif(IS_DEBUG)
  endif(MSVC)  
endmacro(boost_feature_interactions)

# This macro is an internal utility macro that builds a particular
# variant of a boost library.
#
#   boost_library_variant(libname 
#                         feature1 feature2 ...)
#
# where libname is the name of the Boost library (e.g.,
# "boost_filesystem") and feature1, feature2, ... are the features
# that will be used in this variant. 
#
# This macro will define a new library target based on libname and the
# specific variant name (see boost_library_variant_target_name), which
# depends on the utility target libname. The compilation and linking
# flags for this library are defined by THIS_LIB_COMPILE_FLAGS,
# THIS_LIB_LINK_FLAGS, THIS_LIB_LINK_LIBS, and all of the compile and
# linking flags implied by the features provided.
#
# If any of the features listed conflict with this library, no new
# targets will be built. For example, if the library provides the
# option NO_MULTI_THREADED, and one of the features provided is
# MULTI_THREADED, this macro will essentially be a no-op.
macro(boost_library_variant LIBNAME)
  set(THIS_VARIANT_COMPILE_FLAGS "${THIS_LIB_COMPILE_FLAGS}")
  set(THIS_VARIANT_LINK_FLAGS "${THIS_LIB_LINK_FLAGS}")
  set(THIS_VARIANT_LINK_LIBS ${THIS_LIB_LINK_LIBS})
  
  # Determine if it is okay to build this variant
  set(THIS_VARIANT_OKAY TRUE)
  foreach(ARG ${ARGN})
    # If the library itself stated that we cannot build this variant,
    # don't. For example, we're trying to build a shared library
    # variant, but the user specified NO_SHARED in the requirements of
    # the library.
    if (THIS_LIB_NO_${ARG})
      set(THIS_VARIANT_OKAY FALSE)
      set(SELECT_VARIANT_FAILURE_REASONS "NO_${ARG}")
    endif (THIS_LIB_NO_${ARG})

    # If the user specified that we should not build any variants of
    # this kind, don't. For example, if the ENABLE_SHARED option is
    # off, don't build shared libraries.
    if(NOT ENABLE_${ARG})
      set(THIS_VARIANT_OKAY FALSE)
      set(SELECT_VARIANT_FAILURE_REASONS "variant disabled because ENABLE_${ARG} is OFF")
    endif(NOT ENABLE_${ARG})

    # Accumulate compile and link flags
    set(THIS_VARIANT_COMPILE_FLAGS "${THIS_VARIANT_COMPILE_FLAGS} ${THIS_LIB_${ARG}_COMPILE_FLAGS} ${${ARG}_COMPILE_FLAGS}")
    set(THIS_VARIANT_LINK_FLAGS "${THIS_VARIANT_LINK_FLAGS} ${THIS_LIB_${ARG}_LINK_FLAGS} ${${ARG}_LINK_FLAGS}")
    set(THIS_VARIANT_LINK_LIBS ${THIS_VARIANT_LINK_LIBS} ${THIS_LIB_${ARG}_LINK_LIBS} ${${ARG}_LINK_LIBS})
  endforeach(ARG ${ARGN})

  # message("boost_library_variant(${LIBNAME} ${ARGN})")

  # Handle feature interactions
  boost_feature_interactions("THIS_VARIANT" ${ARGN})
  boost_library_variant_target_name(${ARGN})
  # Determine the suffix for this library target
  set(VARIANT_LIBNAME "${LIBNAME}${VARIANT_TARGET_NAME}")
  trace(VARIANT_LIBNAME)

  set(DEPENDENCY_FAILURES "")
  foreach(dep ${THIS_LIB_DEPENDS})
    trace(dep)
    dependency_check("${dep}${VARIANT_TARGET_NAME}")
  endforeach()
  trace(THIS_VARIANT_OKAY)
  trace(DEPENDENCY_FAILURES)

  #
  # Announce dependency failures only if this variant
  # is otherwise OK
  #
  if(THIS_VARIANT_OKAY AND DEPENDENCY_FAILURES)
    set(THIS_VARIANT_OKAY FALSE)
    # separate_arguments(DEPENDENCY_FAILURES)
    colormsg(HIRED "    ${LIBNAME}${VARIANT_TARGET_NAME}" RED "(library) disabled due to dependency failures:")
    foreach (depfail ${DEPENDENCY_FAILURES})
      colormsg(RED "     " YELLOW "${depfail}")
    endforeach()
  endif()

  if (THIS_VARIANT_OKAY)

    # We handle static vs. dynamic libraries differently
    list_contains(THIS_LIB_IS_STATIC "STATIC" ${ARGN})

    if (THIS_LIB_IS_STATIC)

      add_library(${VARIANT_LIBNAME} STATIC ${THIS_LIB_SOURCES})

      # On Windows, we need static and shared libraries to have
      # different names, so we follow the Boost.Build version 2 style
      # and prepend "lib" to the name.
      if(WIN32 AND NOT (CYGWIN OR MINGW))
	set_target_properties(${VARIANT_LIBNAME}
	  PROPERTIES
	  PREFIX "${LIBPREFIX}"
	  )
      endif()
      
      set_target_properties(${VARIANT_LIBNAME}
        PROPERTIES
        OUTPUT_NAME "${LIBNAME}${VARIANT_VERSIONED_NAME}"
        CLEAN_DIRECT_OUTPUT 1
        COMPILE_FLAGS "${THIS_VARIANT_COMPILE_FLAGS}"
        LINK_FLAGS "${THIS_VARIANT_LINK_FLAGS}"
        LABELS "${BOOST_PROJECT_NAME}"
        )

    elseif (THIS_LIB_MODULE)

      add_library(${VARIANT_LIBNAME} MODULE ${THIS_LIB_SOURCES})

      #
      # You don't set SOVERSION here... nothing links "to" these things      		
      #
      set_target_properties(${VARIANT_LIBNAME}
        PROPERTIES
        OUTPUT_NAME ${LIBNAME}
        CLEAN_DIRECT_OUTPUT 1
        COMPILE_FLAGS "${THIS_VARIANT_COMPILE_FLAGS}"
        LINK_FLAGS "${THIS_VARIANT_LINK_FLAGS}"
        LABELS "${BOOST_PROJECT_NAME}"
        PREFIX ""
        )

    else ()  # shared

      add_library(${VARIANT_LIBNAME} SHARED ${THIS_LIB_SOURCES})

      if(MINGW)
	set_target_properties(${VARIANT_LIBNAME}
	  PROPERTIES
	  PREFIX ""
	  )
      endif()

      set_target_properties(${VARIANT_LIBNAME}
        PROPERTIES
        OUTPUT_NAME "${LIBNAME}${VARIANT_VERSIONED_NAME}"
        CLEAN_DIRECT_OUTPUT 1
        COMPILE_FLAGS "${THIS_VARIANT_COMPILE_FLAGS}"
        LINK_FLAGS "${THIS_VARIANT_LINK_FLAGS}"
        LABELS "${BOOST_PROJECT_NAME}"
        )

      if (BUILD_SOVERSIONED)
	set_target_properties(${VARIANT_LIBNAME}
	  PROPERTIES
	  SOVERSION "${BOOST_VERSION}"
	  )
      endif()
    endif ()
    
    # The basic LIBNAME target depends on each of the variants
    add_dependencies(${LIBNAME} ${VARIANT_LIBNAME})

    # Link against whatever libraries this library depends on
    target_link_libraries(${VARIANT_LIBNAME} ${THIS_VARIANT_LINK_LIBS})

    foreach(d ${THIS_LIB_DEPENDS})
      # message(STATUS "linking ${d}")
      target_link_libraries(${VARIANT_LIBNAME} "${d}${VARIANT_TARGET_NAME}")
    endforeach()

    export(TARGETS ${VARIANT_LIBNAME} 
      APPEND
      FILE ${BOOST_EXPORTS_FILE})

    if(NOT THIS_LIB_NO_INSTALL)
      # Setup installation properties
      string(TOLOWER "${BOOST_PROJECT_NAME}${VARIANT_TARGET_NAME}" LIB_COMPONENT)
      string(REPLACE "-" "_" LIB_COMPONENT ${LIB_COMPONENT})
      
      # Installation of this library variant
      string(TOLOWER ${BOOST_PROJECT_NAME} libname)

      #
      # tds:  componentization disabled for the moment
      #
      install(TARGETS ${VARIANT_LIBNAME} 
	EXPORT Boost 
	DESTINATION ${BOOST_LIB_INSTALL_DIR}
	COMPONENT Boost) #${LIB_COMPONENT})

      # set_property( 
      #      TARGET ${VARIANT_LIBNAME}
      #      PROPERTY BOOST_CPACK_COMPONENT
      #      ${LIB_COMPONENT})
      
      # Make the library installation component dependent on the library
      # installation components of dependent libraries.
      trace(THIS_LIB_DEPENDS)
      set(THIS_LIB_COMPONENT_DEPENDS)
      foreach(DEP ${THIS_LIB_DEPENDS})
        # We ask the library variant that this library depends on to tell us
        # what it's associated installation component is. We depend on that 
        # installation component.
        get_property(DEP_COMPONENT 
          TARGET "${DEP}${VARIANT_TARGET_NAME}"
          PROPERTY BOOST_CPACK_COMPONENT)
        
	if (DEP_COMPONENT)
          if (DEP_COMPONENT STREQUAL LIB_COMPONENT)
            # Do nothing: we have library dependencies within one 
            # Boost library
          else()
            list(APPEND THIS_LIB_COMPONENT_DEPENDS ${DEP_COMPONENT})
          endif()
	endif()
      endforeach(DEP)
      
      if (COMMAND cpack_add_component)
        fix_cpack_component_name(CPACK_COMPONENT_GROUP_NAME ${libname})
        cpack_add_component(${LIB_COMPONENT}
          DISPLAY_NAME "${VARIANT_DISPLAY_NAME}"
          GROUP ${CPACK_COMPONENT_GROUP_NAME}
          DEPENDS ${THIS_LIB_COMPONENT_DEPENDS})
      endif ()
    endif(NOT THIS_LIB_NO_INSTALL)
  endif ()
endmacro(boost_library_variant)

# Updates the set of default build variants to account for variations
# in the given feature.
#
#   boost_add_default_variant(feature-val1 feature-val2 ...)
#
# Each new feature creates a new set of build variants using that
# feature. For example, writing:
# 
#    boost_add_default_variant(SINGLE_THREADED MULTI_THREADED)
#
# will create single- and multi-threaded variants of every default
# library variant already defined, doubling the number of variants
# that will be built. See the top-level CMakeLists.txt for the set of
# default variants.
#
# Variables affected:
#
#   BOOST_DEFAULT_VARIANTS:
#     This variable describes all of the variants that will be built
#     by default, and will be updated with each invocation of
#     boost_add_default_variant. The variable itself is a list, where
#     each element in the list contains a colon-separated string
#     naming a specific set of features for that variant, e.g.,
#     STATIC:DEBUG:SINGLE_THREADED.
#
#   BOOST_FEATURES:
#     This variable describes all of the feature sets that we know about,
#     and will be extended each time ither boost_add_default_variant or 
#     boost_add_extra_variant is invoked. This macro will contain a list
#     of feature sets, each containing the values for a given feature
#     separated by colons, e.g., "DEBUG:RELEASE".
#
#   BOOST_ADD_ARG_NAMES:
#     This variable describes all of the feature-specific arguments
#     that can be used for the boost_add_library macro, separated by
#     semicolons. For example, given the use of
#     boost_add_default_variant above, this variable will contain (at
#     least)
#
#        SINGLE_THREADED_COMPILE_FLAGS;SINGLE_THREADED_LINK_FLAGS;
#        MULTI_THREADED_COMPILE_FLAGS;MULTI_THREADED_LINK_FLAGS
#
#     When this variable is used in boost_add_library, it turns these
#     names into feature-specific options. For example,
#     MULTI_THREADED_COMPILE_FLAGS provides extra compile flags to be
#     used only for multi-threaded variants of the library.
#
#   BOOST_ADDLIB_OPTION_NAMES:
#     Like BOOST_ADD_ARG_NAMES, this variable describes
#     feature-specific options to boost_add_library that can be used to
#     turn off building of the library when the variant would require
#     certain features. For example, the NO_SINGLE_THREADED option
#     turns off building of single-threaded variants for a library.
#
#   BOOST_ADDEXE_OPTION_NAMES:
#     Like BOOST_ADDLIB_OPTION_NAMES, except that that variable 
#     describes options to boost_add_executable that can be used to
#     describe which features are needed to build the executable.
#     For example, the MULTI_THREADED option requires that the 
#     executable be built against multi-threaded libraries and with
#     multi-threaded options.
macro(boost_add_default_variant)
  # Update BOOST_DEFAULT_VARIANTS
  if (BOOST_DEFAULT_VARIANTS)
    set(BOOST_DEFAULT_VARIANTS_ORIG ${BOOST_DEFAULT_VARIANTS})
    set(BOOST_DEFAULT_VARIANTS)
    foreach(VARIANT ${BOOST_DEFAULT_VARIANTS_ORIG})
      foreach(FEATURE ${ARGN})
        list(APPEND BOOST_DEFAULT_VARIANTS "${VARIANT}:${FEATURE}")
      endforeach(FEATURE ${ARGN})
    endforeach(VARIANT ${BOOST_DEFAULT_VARIANTS_ORIG})
    set(BOOST_DEFAULT_VARIANTS_ORIG)
  else (BOOST_DEFAULT_VARIANTS)
    set(BOOST_DEFAULT_VARIANTS ${ARGN})
  endif (BOOST_DEFAULT_VARIANTS)

  # Set Feature flag options used by the boost_library macro and the
  # BOOST_FEATURES variable
  set(BOOST_DEFVAR_FEATURES)
  foreach(FEATURE ${ARGN})
    set(BOOST_ADD_ARG_NAMES 
      "${BOOST_ADD_ARG_NAMES};${FEATURE}_COMPILE_FLAGS;${FEATURE}_LINK_FLAGS;${FEATURE}_LINK_LIBS")
    set(BOOST_ADDLIB_OPTION_NAMES "${BOOST_ADDLIB_OPTION_NAMES};NO_${FEATURE}")
    set(BOOST_ADDEXE_OPTION_NAMES "${BOOST_ADDEXE_OPTION_NAMES};${FEATURE}")
    if (BOOST_DEFVAR_FEATURES)
      set(BOOST_DEFVAR_FEATURES "${BOOST_DEFVAR_FEATURES}:${FEATURE}")
    else (BOOST_DEFVAR_FEATURES)
      set(BOOST_DEFVAR_FEATURES "${FEATURE}")
    endif (BOOST_DEFVAR_FEATURES)
  endforeach(FEATURE ${ARGN})
  list(APPEND BOOST_FEATURES ${BOOST_DEFVAR_FEATURES})
endmacro(boost_add_default_variant)

# Updates the set of "extra" build variants, which may be used to
# generate extra, library-specific variants of libraries.
#
#   boost_add_extra_variant(feature-val1 feature-val2 ...)
#
# Each extra viarant makes it possible for libraries to define extra
# variants.  For example, writing:
# 
#    boost_add_extra_variant(PYTHON_NODEBUG PYTHON_DEBUG)
#
# creates a PYTHON_NODEBUG/PYTHON_DEBUG feature pair as an extra
# variant, used by the Boost.Python library, which generates separate
# variants of the Boost.Python library: one variant uses the Python
# debug libraries, the other does not.
#
# The difference between boost_add_default_variant and
# boost_add_extra_variant is that adding a new default variant
# introduces additional variants to *all* Boost libraries, unless
# those variants are explicitly excluded by the library. Adding a new
# extra variant, on the other hand, allows libraries to specifically
# request extra variants using that feature.
#
# Variables affected:
#
#   BOOST_FEATURES:
#     See boost_add_default_variant.
#
#   BOOST_ADD_ARG_NAMES: 
#     See boost_add_default_variant.
#
#   BOOST_ADDLIB_OPTION_NAMES:
#     See boost_add_default_variant.
#
#   BOOST_ADDEXE_OPTION_NAMES:
#     See boost_add_default_variant.
macro(boost_add_extra_variant)
  set(BOOST_EXTVAR_FEATURES)
  foreach(FEATURE ${ARGN})
    set(BOOST_ADD_ARG_NAMES 
      "${BOOST_ADD_ARG_NAMES};${FEATURE}_COMPILE_FLAGS;${FEATURE}_LINK_FLAGS;${FEATURE}_LINK_LIBS")
    set(BOOST_ADDLIB_OPTION_NAMES "${BOOST_ADDLIB_OPTION_NAMES};NO_${FEATURE}")
    set(BOOST_ADDEXE_OPTION_NAMES "${BOOST_ADDEXE_OPTION_NAMES};${FEATURE}")
    if (BOOST_EXTVAR_FEATURES)
      set(BOOST_EXTVAR_FEATURES "${BOOST_EXTVAR_FEATURES}:${FEATURE}")
    else (BOOST_EXTVAR_FEATURES)
      set(BOOST_EXTVAR_FEATURES "${FEATURE}")
    endif (BOOST_EXTVAR_FEATURES)
  endforeach(FEATURE ${ARGN})  
  list(APPEND BOOST_FEATURES ${BOOST_EXTVAR_FEATURES})
endmacro(boost_add_extra_variant)

# Compute the variant that will be used to build this executable or
# module, taking into account both the requested features passed to
# boost_add_executable or boost_add_library and what options the user
# has set.
macro(boost_select_variant NAME PREFIX)
  set(${PREFIX}_DEBUG_AND_RELEASE FALSE)
  set(SELECT_VARIANT_OKAY TRUE)
  set(SELECT_VARIANT_FAILURE_REASONS)
  set(${PREFIX}_VARIANT)

  foreach(FEATURESET_STR ${BOOST_FEATURES})
    trace(FEATURESET_STR)

    string(REPLACE ":" ";" FEATURESET ${FEATURESET_STR})
    separate_arguments(FEATURESET)
    set(${PREFIX}_REQUESTED_FROM_SET FALSE)
    foreach (FEATURE ${FEATURESET})
      trace(FEATURE)

      if (${PREFIX}_${FEATURE} AND ENABLE_${FEATURE})
	trace(${PREFIX}_${FEATURE})
	set(${PREFIX}_REQUESTED_FROM_SET TRUE)
	list(APPEND ${PREFIX}_VARIANT ${FEATURE})
      endif()

      #       if ((NOT userpref_selected) AND ENABLE_${FEATURE})
      # 	# message("YES ${PREFIX}_${FEATURE}")
      #         # Make this feature part of the variant
      #         list(APPEND ${PREFIX}_VARIANT ${FEATURE})
      #         set(${PREFIX}_REQUESTED_FROM_SET TRUE)
      # 
      #         # The caller has requested this particular feature be used
      #         # when building the executable or module. If we can't satisfy
      #         # that request (because the user has turned off the build
      #         # variants with that feature), then we won't build this
      #         # executable or module.
      #         if (NOT ENABLE_${FEATURE})
      # 	  message("NOT ENABLE_${FEATURE}")
      #           set(SELECT_VARIANT_OKAY FALSE)
      # 	  list(APPEND SELECT_VARIANT_FAILURE_REASONS 
      # 	    "ENABLE_${FEATURE} iz FALSE")
      #         else()
      # 	  set(unselected FALSE)
      #         endif()
      #       endif()
    endforeach()

    if (NOT ${PREFIX}_REQUESTED_FROM_SET)
      # The caller did not specify which feature value to use from
      # this set, so find the first feature value that actually works.
      set(${PREFIX}_FOUND_FEATURE FALSE)

      trace(${PREFIX}_FOUND_FEATURE)
      # If this feature set decides between Release and Debug, we
      # either query CMAKE_BUILD_TYPE to determine which to use (for
      # makefile targets) or handle both variants separately (for IDE
      # targets). We only build both variants separately for executable targets.
      if (FEATURESET_STR STREQUAL "RELEASE:DEBUG")
	trace(CMAKE_CONFIGURATION_TYPES)
        if (CMAKE_CONFIGURATION_TYPES)
          # IDE target: can we build both debug and release?
          if (ENABLE_DEBUG AND ENABLE_RELEASE)
            if (${PREFIX} STREQUAL "THIS_EXE")
              # Remember that we're capable of building both configurations
              set(${PREFIX}_DEBUG_AND_RELEASE TRUE)

              # Don't add RELEASE or DEBUG to the variant (yet)
              set(${PREFIX}_FOUND_FEATURE TRUE)
            endif ()
          endif ()
        else ()
          # Makefile target: CMAKE_BUILD_TYPE tells us which variant to build
	  trace(CMAKE_BUILD_TYPE)
          if (CMAKE_BUILD_TYPE STREQUAL "Release" AND ENABLE_RELEASE)
            # Okay, build the release variant
            list(APPEND ${PREFIX}_VARIANT RELEASE)
            set(${PREFIX}_FOUND_FEATURE TRUE)
          elseif (CMAKE_BUILD_TYPE STREQUAL "Debug" AND ENABLE_DEBUG)
            # Okay, build the debug variant
            list(APPEND ${PREFIX}_VARIANT DEBUG)
            set(${PREFIX}_FOUND_FEATURE TRUE)
          endif ()
        endif ()
      endif ()

      # Search through all of the features in the set to find one that works
      foreach (FEATURE ${FEATURESET})
        # We only care about the first feature value we find...
        if (NOT ${PREFIX}_FOUND_FEATURE)
          # Are we allowed to build this feature?
          if (ENABLE_${FEATURE})
            # Found it: we're done
            list(APPEND ${PREFIX}_VARIANT ${FEATURE})
            set(${PREFIX}_FOUND_FEATURE TRUE)
          endif (ENABLE_${FEATURE})
        endif (NOT ${PREFIX}_FOUND_FEATURE)
      endforeach (FEATURE ${FEATURESET})

      if (NOT ${PREFIX}_FOUND_FEATURE)
        # All of the features in this set were turned off. 
        # Just don't build anything.
        set(SELECT_VARIANT_OKAY FALSE)
	# message("NOT ${PREFIX}_FOUND_FEATURE")
      endif (NOT ${PREFIX}_FOUND_FEATURE)
    endif (NOT ${PREFIX}_REQUESTED_FROM_SET)
  endforeach(FEATURESET_STR ${BOOST_FEATURES})
  
  # Propagate flags from each of the features
  if (SELECT_VARIANT_OKAY)
    foreach (FEATURE ${${PREFIX}_VARIANT})
      # Add all of the flags for this feature
      set(${PREFIX}_COMPILE_FLAGS 
        "${${PREFIX}_COMPILE_FLAGS} ${${PREFIX}_${FEATURE}_COMPILE_FLAGS} ${${FEATURE}_COMPILE_FLAGS}")
      set(${PREFIX}_LINK_FLAGS 
        "${${PREFIX}_LINK_FLAGS} ${${PREFIX}_${FEATURE}_LINK_FLAGS} ${${FEATURE}_LINK_FLAGS}")
      if (${PREFIX} STREQUAL "THIS_EXE")
        set(${PREFIX}_LINK_FLAGS 
          "${${PREFIX}_LINK_FLAGS} ${${FEATURE}_EXE_LINK_FLAGS}")
      endif()
      set(${PREFIX}_LINK_LIBS 
        ${${PREFIX}_LINK_LIBS} ${${PREFIX}_${FEATURE}_LINK_LIBS} ${${FEATURE}_LINK_LIBS})
    endforeach (FEATURE ${${PREFIX}_VARIANT})

    # Handle feature interactions
    boost_feature_interactions("${PREFIX}" ${${PREFIX}_VARIANT})
  else ()
    set(${PREFIX}_VARIANT)
  endif ()
endmacro(boost_select_variant)

# Creates a new Boost library target that generates a compiled library
# (.a, .lib, .dll, .so, etc) from source files. This routine will
# actually build several different variants of the same library, with
# different compilation options, as determined by the set of "default"
# library variants.
#
#   boost_add_library(libname
#                     source1 source2 ...
#                     [COMPILE_FLAGS compileflags]
#                     [feature_COMPILE_FLAGS compileflags]
#                     [LINK_FLAGS linkflags]
#                     [feature_LINK_FLAGS linkflags]
#                     [LINK_LIBS linklibs]
#                     [feature_LINK_LIBS linklibs]
#                     [DEPENDS libdepend1 libdepend2 ...]
#                     [MODULE]
#                     [NO_feature]
#                     [EXTRA_VARIANTS variant1 variant2 ...]
#                     [FORCE_VARIANTS variant1])
#
# where libname is the name of Boost library binary (e.g.,
# "boost_regex") and source1, source2, etc. are the source files used
# to build the library, e.g., cregex.cpp.
#
# This macro has a variety of options that affect its behavior. In
# several cases, we use the placeholder "feature" in the option name
# to indicate that there are actually several different kinds of
# options, each referring to a different build feature, e.g., shared
# libraries, multi-threaded, debug build, etc. For a complete listing
# of these features, please refer to the CMakeLists.txt file in the
# root of the Boost distribution, which defines the set of features
# that will be used to build Boost libraries by default.
#
# The options that affect this macro's behavior are:
#
#   COMPILE_FLAGS: Provides additional compilation flags that will be
#   used when building all variants of the library. For example, one
#   might want to add "-DBOOST_SIGNALS_NO_LIB=1" through this option
#   (which turns off auto-linking for the Signals library while
#   building it).
#
#   feature_COMPILE_FLAGS: Provides additional compilation flags that
#   will be used only when building variants of the library that
#   include the given feature. For example,
#   MULTI_THREADED_COMPILE_FLAGS are additional flags that will be
#   used when building a multi-threaded variant, while
#   SHARED_COMPILE_FLAGS will be used when building a shared library
#   (as opposed to a static library).
#
#   LINK_FLAGS: Provides additional flags that will be passed to the
#   linker when linking each variant of the library. This option
#   should not be used to link in additional libraries; see LINK_LIBS
#   and DEPENDS.
#
#   feature_LINK_FLAGS: Provides additional flags that will be passed
#   to the linker when building variants of the library that contain a
#   specific feature, e.g., MULTI_THREADED_LINK_FLAGS. This option
#   should not be used to link in additional libraries; see
#   feature_LINK_LIBS.
#
#   LINK_LIBS: Provides additional libraries against which each of the
#   library variants will be linked. For example, one might provide
#   "expat" as options to LINK_LIBS, to state that each of the library
#   variants will link against the expat library binary. Use LINK_LIBS
#   for libraries external to Boost; for Boost libraries, use DEPENDS.
#
#   feature_LINK_LIBS: Provides additional libraries for specific
#   variants of the library to link against. For example,
#   MULTI_THREADED_LINK_LIBS provides extra libraries to link into
#   multi-threaded variants of the library.
#
#   DEPENDS: States that this Boost library depends on and links
#   against another Boost library. The arguments to DEPENDS should be
#   the unversioned name of the Boost library, such as
#   "boost_filesystem". Like LINK_LIBS, this option states that all
#   variants of the library being built will link against the stated
#   libraries. Unlike LINK_LIBS, however, DEPENDS takes particular
#   library variants into account, always linking the variant of one
#   Boost library against the same variant of the other Boost
#   library. For example, if the boost_mpi_python library DEPENDS on
#   boost_python, multi-threaded variants of boost_mpi_python will
#   link against multi-threaded variants of boost_python.
#
#   MODULE: This option states that, when building a shared library,
#   the shared library should be built as a module rather than a
#   normal shared library. Modules have special meaning an behavior on
#   some platforms, such as Mac OS X.
#
#   NO_feature: States that library variants containing a particular
#   feature should not be built. For example, passing
#   NO_SINGLE_THREADED suppresses generation of single-threaded
#   variants of this library.
#
#   EXTRA_VARIANTS: Specifies that extra variants of this library
#   should be built, based on the features listed. Each "variant" is a 
#   colon-separated list of features. For example, passing
#     EXTRA_VARIANTS "PYTHON_NODEBUG:PYTHON_DEBUG"
#   will result in the creation of an extra set of library variants,
#   some with the PYTHON_NODEBUG feature and some with the
#   PYTHON_DEBUG feature. 
#
#   FORCE_VARIANTS: This will force the build system to ALWAYS build this 
#   variant of the library not matter what variants are set.
#
# Example:
#   boost_add_library(
#     boost_thread
#     barrier.cpp condition.cpp exceptions.cpp mutex.cpp once.cpp 
#     recursive_mutex.cpp thread.cpp tss_hooks.cpp tss_dll.cpp tss_pe.cpp 
#     tss.cpp xtime.cpp
#     SHARED_COMPILE_FLAGS "-DBOOST_THREAD_BUILD_DLL=1"
#     STATIC_COMPILE_FLAGS "-DBOOST_THREAD_BUILD_LIB=1"
#     NO_SINGLE_THREADED
#   )
macro(boost_add_library SHORT_LIBNAME)
  set(LIBNAME "boost_${SHORT_LIBNAME}")
  parse_arguments(THIS_LIB
    "DEPENDS;COMPILE_FLAGS;LINK_FLAGS;LINK_LIBS;EXTRA_VARIANTS;FORCE_VARIANTS;${BOOST_ADD_ARG_NAMES}"
    "MODULE;NO_INSTALL;${BOOST_ADDLIB_OPTION_NAMES}"
    ${ARGN}
    )

  set(THIS_LIB_SOURCES ${THIS_LIB_DEFAULT_ARGS})

  #
  # cmake BoostConfig.cmake generation needs to know which
  # libraries are available
  #
  set(BOOST_ALL_COMPONENTS ${SHORT_LIBNAME} ${BOOST_ALL_COMPONENTS} 
    PARENT_SCOPE)

  # A top-level target that refers to all of the variants of the
  # library, collectively.
  add_custom_target(${LIBNAME})

  if (THIS_LIB_EXTRA_VARIANTS)
    # Build the set of variants that we will generate for this library
    set(THIS_LIB_VARIANTS)
    foreach(VARIANT ${BOOST_DEFAULT_VARIANTS})
      foreach(EXTRA_VARIANT ${THIS_LIB_EXTRA_VARIANTS})
        string(REPLACE ":" ";" FEATURES "${EXTRA_VARIANT}")
        separate_arguments(FEATURES)
        foreach(FEATURE ${FEATURES})
          list(APPEND THIS_LIB_VARIANTS "${VARIANT}:${FEATURE}")
        endforeach(FEATURE ${FEATURES})
      endforeach(EXTRA_VARIANT ${THIS_LIB_EXTRA_VARIANTS})
    endforeach(VARIANT ${BOOST_DEFAULT_VARIANTS})
  else (THIS_LIB_EXTRA_VARIANTS)
    set(THIS_LIB_VARIANTS ${BOOST_DEFAULT_VARIANTS})
  endif (THIS_LIB_EXTRA_VARIANTS)
  
  if (THIS_LIB_FORCE_VARIANTS)
    #  string(TOUPPER "${LIBNAME}_FORCE_VARIANTS" force_variants)
    #  set(${force_variants} ${THIS_LIB_FORCE_VARIANTS} CACHE INTERNAL "")
    set(ENABLE_${THIS_LIB_FORCE_VARIANTS}_PREV ${ENABLE_${THIS_LIB_FORCE_VARIANTS}} )
    set(ENABLE_${THIS_LIB_FORCE_VARIANTS} TRUE)
  endif (THIS_LIB_FORCE_VARIANTS)
  
  # Build each of the library variants
  foreach(VARIANT_STR ${THIS_LIB_VARIANTS})
    string(REPLACE ":" ";" VARIANT ${VARIANT_STR})
    separate_arguments(VARIANT)
    # message("VARIANT=${VARIANT}")
    boost_library_variant(${LIBNAME} ${VARIANT})
  endforeach(VARIANT_STR ${THIS_LIB_VARIANTS})
  
  if (THIS_LIB_FORCE_VARIANTS)
    set(ENABLE_${THIS_LIB_FORCE_VARIANTS} ${ENABLE_${THIS_LIB_FORCE_VARIANTS}_PREV} )
    # message(STATUS "* ^^ ENABLE_${THIS_LIB_FORCE_VARIANTS}  ${ENABLE_${THIS_LIB_FORCE_VARIANTS}}")
  endif (THIS_LIB_FORCE_VARIANTS)  
endmacro(boost_add_library)

# Creates a new executable from source files.
#
#   boost_add_executable(exename
#                        source1 source2 ...
#                        [COMPILE_FLAGS compileflags]
#                        [feature_COMPILE_FLAGS compileflags]
#                        [LINK_FLAGS linkflags]
#                        [feature_LINK_FLAGS linkflags]
#                        [LINK_LIBS linklibs]
#                        [feature_LINK_LIBS linklibs]
#                        [DEPENDS libdepend1 libdepend2 ...]
#                        [feature]
#                        [NO_INSTALL])
#
# where exename is the name of the executable (e.g., "wave").  source1,
# source2, etc. are the source files used to build the executable, e.g.,
# cpp.cpp. If no source files are provided, "exename.cpp" will be
# used.
#
# This macro has a variety of options that affect its behavior. In
# several cases, we use the placeholder "feature" in the option name
# to indicate that there are actually several different kinds of
# options, each referring to a different build feature, e.g., shared
# libraries, multi-threaded, debug build, etc. For a complete listing
# of these features, please refer to the CMakeLists.txt file in the
# root of the Boost distribution, which defines the set of features
# that will be used to build Boost libraries by default.
#
# The options that affect this macro's behavior are:
#
#   COMPILE_FLAGS: Provides additional compilation flags that will be
#   used when building the executable.
#
#   feature_COMPILE_FLAGS: Provides additional compilation flags that
#   will be used only when building the executable with the given
#   feature (e.g., SHARED_COMPILE_FLAGS when we're linking against
#   shared libraries). Note that the set of features used to build the
#   executable depends both on the arguments given to
#   boost_add_executable (see the "feature" argument description,
#   below) and on the user's choice of variants to build.
#
#   LINK_FLAGS: Provides additional flags that will be passed to the
#   linker when linking the executable. This option should not be used
#   to link in additional libraries; see LINK_LIBS and DEPENDS.
#
#   feature_LINK_FLAGS: Provides additional flags that will be passed
#   to the linker when linking the executable with the given feature
#   (e.g., MULTI_THREADED_LINK_FLAGS when we're linking a
#   multi-threaded executable).
#
#   LINK_LIBS: Provides additional libraries against which the
#   executable will be linked. For example, one might provide "expat"
#   as options to LINK_LIBS, to state that the executable will link
#   against the expat library binary. Use LINK_LIBS for libraries
#   external to Boost; for Boost libraries, use DEPENDS.
#
#   feature_LINK_LIBS: Provides additional libraries to link against
#   when linking an executable built with the given feature. 
#
#   DEPENDS: States that this executable depends on and links against
#   a Boostlibrary. The arguments to DEPENDS should be the unversioned
#   name of the Boost library, such as "boost_filesystem". Like
#   LINK_LIBS, this option states that the executable will link
#   against the stated libraries. Unlike LINK_LIBS, however, DEPENDS
#   takes particular library variants into account, always linking to
#   the appropriate variant of a Boost library. For example, if the
#   MULTI_THREADED feature was requested in the call to
#   boost_add_executable, DEPENDS will ensure that we only link
#   against multi-threaded libraries.
#
#   feature: States that the executable should always be built using a
#   given feature, e.g., SHARED linking (against its libraries) or
#   MULTI_THREADED (for multi-threaded builds). If that feature has
#   been turned off by the user, the executable will not build.
#
#   NO_INSTALL: Don't install this executable with the rest of Boost.
#
#   OUTPUT_NAME: If you want the executable to be generated somewhere
#   other than the binary directory, pass the path (including
#   directory and file name) via the OUTPUT_NAME parameter.
#
# Example:
#   boost_add_executable(wave cpp.cpp 
#     DEPENDS boost_wave boost_program_options boost_filesystem 
#             boost_serialization
#     )
macro(boost_add_executable EXENAME)
  # Note: ARGS is here to support the use of boost_add_executable in
  # the testing code.
  parse_arguments(THIS_EXE
    "DEPENDS;COMPILE_FLAGS;LINK_FLAGS;LINK_LIBS;OUTPUT_NAME;ARGS;TARGET_PREFIX;${BOOST_ADD_ARG_NAMES}"
    "NO_INSTALL;${BOOST_ADDEXE_OPTION_NAMES}"
    ${ARGN}
    )

  # Determine the list of sources
  if (THIS_EXE_DEFAULT_ARGS)
    set(THIS_EXE_SOURCES ${THIS_EXE_DEFAULT_ARGS})
  else (THIS_EXE_DEFAULT_ARGS)
    set(THIS_EXE_SOURCES ${EXENAME}.cpp)
  endif (THIS_EXE_DEFAULT_ARGS)

  # Whether we can build both debug and release versions of this
  # executable within an IDE (based on the selected configuration
  # type).
  set(THIS_EXE_DEBUG_AND_RELEASE FALSE)
  
  # Compute the variant that will be used to build this executable,
  # taking into account both the requested features passed to
  # boost_add_executable and what options the user has set.
  boost_select_variant(${EXENAME} THIS_EXE)

  # message("THIS_EXE_VARIANT=${THIS_EXE_VARIANT}")
  # Possibly hyphenate exe's name
  if (THIS_PROJECT_IS_TOOL)
    set(THIS_EXE_NAME ${THIS_EXE_TARGET_PREFIX}${EXENAME})
  else()
    set(THIS_EXE_NAME ${BOOST_PROJECT_NAME}-${THIS_EXE_TARGET_PREFIX}${EXENAME})
  endif()

  # Compute the name of the variant targets that we'll be linking
  # against. We'll use this to link against the appropriate
  # dependencies. For IDE targets where we can build both debug and
  # release configurations, create DEBUG_ and RELEASE_ versions of
  # the macros.
  if (THIS_EXE_DEBUG_AND_RELEASE)
    boost_library_variant_target_name(RELEASE ${THIS_EXE_VARIANT})
    set(RELEASE_VARIANT_TARGET_NAME "${VARIANT_TARGET_NAME}")
    boost_library_variant_target_name(DEBUG ${THIS_EXE_VARIANT})
    set(DEBUG_VARIANT_TARGET_NAME "${VARIANT_TARGET_NAME}")
  else (THIS_EXE_DEBUG_AND_RELEASE)
    boost_library_variant_target_name(${THIS_EXE_VARIANT})
  endif (THIS_EXE_DEBUG_AND_RELEASE)

  # Compute the actual set of library dependencies, based on the
  # variant name we computed above. The RELEASE and DEBUG versions
  # only apply when THIS_EXE_DEBUG_AND_RELEASE.
  set(THIS_EXE_ACTUAL_DEPENDS)
  set(THIS_EXE_RELEASE_ACTUAL_DEPENDS)
  set(THIS_EXE_DEBUG_ACTUAL_DEPENDS)
  set(DEPENDENCY_FAILURES "")
  foreach(LIB ${THIS_EXE_DEPENDS})
    if (LIB MATCHES ".*-.*")
      # The user tried to state exactly which variant to use. Just
      # propagate the dependency and hope that s/he was
      # right. Eventually, this should at least warn, because it is
      # not the "proper" way to do things
      list(APPEND THIS_EXE_ACTUAL_DEPENDS ${LIB})
      list(APPEND THIS_EXE_RELEASE_ACTUAL_DEPENDS ${LIB})
      list(APPEND THIS_EXE_DEBUG_ACTUAL_DEPENDS ${LIB})
      dependency_check(${LIB})
    else ()
      # The user has given the name of just the library target,
      # e.g., "boost_filesystem". We add on the appropriate variant
      # name(s).
      list(APPEND THIS_EXE_ACTUAL_DEPENDS "${LIB}${VARIANT_TARGET_NAME}")
      list(APPEND THIS_EXE_RELEASE_ACTUAL_DEPENDS "${LIB}${RELEASE_VARIANT_TARGET_NAME}")
      list(APPEND THIS_EXE_DEBUG_ACTUAL_DEPENDS "${LIB}${DEBUG_VARIANT_TARGET_NAME}")
      if(THIS_EXE_RELEASE_AND_DEBUG)
	dependency_check("${LIB}${RELEASE_VARIANT_TARGET_NAME}")
	dependency_check("${LIB}${DEBUG_VARIANT_TARGET_NAME}")
      else()
	dependency_check("${LIB}${VARIANT_TARGET_NAME}")
      endif()
    endif ()
  endforeach()

  set(THIS_EXE_OKAY TRUE)

  if(DEPENDENCY_FAILURES)
    set(THIS_EXE_OKAY FALSE)
    # separate_arguments(DEPENDENCY_FAILURES)
    colormsg(HIRED "    ${THIS_EXE_NAME}" RED "(executable) disabled due to dependency failures:")
    colormsg("      ${DEPENDENCY_FAILURES}")
  endif()

  trace(THIS_EXE_VARIANT)
  trace(THIS_EXE_OUTPUT_NAME)
  if (THIS_EXE_VARIANT AND (NOT DEPENDENCY_FAILURES))
    # It's okay to build this executable

    add_executable(${THIS_EXE_NAME} ${THIS_EXE_SOURCES})
    
    # Set the various compilation and linking flags
    set_target_properties(${THIS_EXE_NAME}
      PROPERTIES
      COMPILE_FLAGS "${THIS_EXE_COMPILE_FLAGS}"
      LINK_FLAGS "${THIS_EXE_LINK_FLAGS}"
      LABELS "${BOOST_PROJECT_NAME}"
      )

    # For IDE generators where we can build both debug and release
    # configurations, pass the configurations along separately.
    if (THIS_EXE_DEBUG_AND_RELEASE)
      set_target_properties(${THIS_EXE_NAME}
        PROPERTIES
        COMPILE_FLAGS_DEBUG "${DEBUG_COMPILE_FLAGS} ${THIS_EXE_COMPILE_FLAGS}"
        COMPILE_FLAGS_RELEASE "${RELEASE_COMPILE_FLAGS} ${THIS_EXE_COMPILE_FLAGS}"
        LINK_FLAGS_DEBUG "${DEBUG_LINK_FLAGS} ${DEBUG_EXE_LINK_FLAGS} ${THIS_EXE_LINK_FLAGS}"
        LINK_FLAGS_RELEASE "${RELEASE_LINK_FLAGS} ${RELEASE_EXE_LINK_FLAGS} ${THIS_EXE_LINK_FLAGS}"
        )
    endif (THIS_EXE_DEBUG_AND_RELEASE)

    # If the user gave an output name, use it.
    if(THIS_EXE_OUTPUT_NAME)
      set_target_properties(${THIS_EXE_NAME}
        PROPERTIES
        OUTPUT_NAME ${THIS_EXE_OUTPUT_NAME}
        )
    endif()

    # Link against the various libraries 
    if (THIS_EXE_DEBUG_AND_RELEASE)
      # Configuration-agnostic libraries
      target_link_libraries(${THIS_EXE_NAME} ${THIS_EXE_LINK_LIBS})
      
      foreach(LIB ${THIS_EXE_RELEASE_ACTUAL_DEPENDS} ${THIS_EXE_RELEASE_LINK_LIBS})     
        target_link_libraries(${THIS_EXE_NAME} optimized ${LIB})
      endforeach(LIB ${THIS_EXE_RELEASE_ACTUAL_DEPENDS} ${THIS_EXE_RELEASE_LINK_LIBS})     
      
      foreach(LIB ${THIS_EXE_DEBUG_ACTUAL_DEPENDS} ${THIS_EXE_DEBUG_LINK_LIBS})     
        target_link_libraries(${THIS_EXE_NAME} debug ${LIB})
      endforeach(LIB ${THIS_EXE_DEBUG_ACTUAL_DEPENDS} ${THIS_EXE_DEBUG_LINK_LIBS})     

    else (THIS_EXE_DEBUG_AND_RELEASE)
      target_link_libraries(${THIS_EXE_NAME} 
        ${THIS_EXE_ACTUAL_DEPENDS} 
        ${THIS_EXE_LINK_LIBS})
    endif (THIS_EXE_DEBUG_AND_RELEASE)

  endif ()
endmacro(boost_add_executable)


# Like boost_add_library, but builds a single library variant
# FIXME: I'm not sure if I like this or not. Document it if it survives.
macro(boost_add_single_library LIBNAME)
  parse_arguments(THIS_LIB
    "DEPENDS;COMPILE_FLAGS;LINK_FLAGS;LINK_LIBS;${BOOST_ADD_ARG_NAMES}"
    "NO_INSTALL;MODULE;${BOOST_ADDEXE_OPTION_NAMES}"
    ${ARGN}
    )
  set(THIS_LIB_SOURCES ${THIS_LIB_DEFAULT_ARGS})

  boost_select_variant(${LIBNAME} THIS_LIB)
  trace(THIS_LIB_VARIANT)
  if (THIS_LIB_VARIANT)
    add_custom_target(${LIBNAME})
    separate_arguments(THIS_LIB_VARIANT)
    boost_library_variant(${LIBNAME} ${THIS_LIB_VARIANT})
  endif ()
endmacro(boost_add_single_library)


#
#  Macro for building boost.python extensions
#
macro(boost_python_extension MODULE_NAME)
  parse_arguments(BPL_EXT 
    "" 
    "" 
    ${ARGN})
  
  if (WIN32)
    set(extlibtype SHARED)
  else()
    set(extlibtype MODULE)
  endif()

  boost_add_single_library(
    ${MODULE_NAME}
    ${BPL_EXT_DEFAULT_ARGS}
    ${extlibtype}
    LINK_LIBS ${PYTHON_LIBRARIES}
    DEPENDS boost_python
    SHARED
    MULTI_THREADED
    )

  if(WIN32)
    set_target_properties(${VARIANT_LIBNAME}
      PROPERTIES
      OUTPUT_NAME "${MODULE_NAME}"
      PREFIX ""
      SUFFIX .pyd
      IMPORT_SUFFIX .pyd
      )
  else()
    set_target_properties(${VARIANT_LIBNAME}
      PROPERTIES
      OUTPUT_NAME "${MODULE_NAME}"
      PREFIX ""
      )
  endif()
  if (NOT THIS_VARIANT_OKAY)
    colormsg(HIRED "    ${MODULE_NAME}" RED "(python extension) disabled because:")
    foreach(msg ${SELECT_VARIANT_FAILURE_REASONS})
      colormsg(YELLOW "      ${msg}")
    endforeach()
  endif()

endmacro()
