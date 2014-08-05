#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
set (BOOST_REGEX_ICU_LIBRARIES)

if (ICU_FOUND AND ICU_I18N_FOUND)
  add_definitions (-DBOOST_HAS_ICU=1)
  include_directories (${ICU_INCLUDE_DIRS})
  set (BOOST_REGEX_ICU_LIBRARIES ${ICU_LIBRARIES} ${ICU_I18N_LIBRARIES})
  colormsg (GREEN "+-- ICU (unicode) available for regex, enabling support.")
  set (NO_STATIC_IF_ICU_FOUND "NO_STATIC")
else (ICU_FOUND AND ICU_I18N_FOUND)
  colormsg (CYAN "+-- ICU (unicode) not available for regex, disabling support.")
endif (ICU_FOUND AND ICU_I18N_FOUND)
 
#
boost_add_library (regex
  c_regex_traits.cpp
  cpp_regex_traits.cpp
  cregex.cpp
  fileiter.cpp
  icu.cpp
  instances.cpp
  posix_api.cpp
  regex.cpp
  regex_debug.cpp
  regex_raw_buffer.cpp
  regex_traits_defaults.cpp
  static_mutex.cpp
  w32_regex_traits.cpp
  wc_regex_traits.cpp
  wide_posix_api.cpp
  winstances.cpp 
  usinstances.cpp 

  LINK_LIBS ${BOOST_REGEX_ICU_LIBRARIES}
  SHARED_COMPILE_FLAGS -DBOOST_REGEX_DYN_LINK=1
  ${NO_STATIC_IF_ICU_FOUND}
  )




