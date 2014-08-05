#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
set (BOOST_LOCALE_ICU_LIBRARIES)

if (ICU_FOUND AND ICU_I18N_FOUND)
  add_definitions (-DBOOST_HAS_ICU=1 -DBOOST_LOCALE_WITH_ICU=1)
  include_directories (${ICU_INCLUDE_DIRS})
  set (BOOST_LOCALE_ICU_LIBRARIES ${ICU_LIBRARIES} ${ICU_I18N_LIBRARIES})
  colormsg (GREEN "+-- ICU (unicode) available for locale, enabling support.")
  set (NO_STATIC_IF_ICU_FOUND NO_STATIC NO_SINGLE_THREADED)
  set (ICU_SOURCES icu/boundary.cpp icu/codecvt.cpp icu/collator.cpp
       icu/conversion.cpp icu/date_time.cpp icu/formatter.cpp
       icu/icu_backend.cpp icu/numeric.cpp icu/time_zone.cpp )
  set (ICU_DEPENDS boost_thread)
else (ICU_FOUND AND ICU_I18N_FOUND)
  colormsg (CYAN "+-- ICU (unicode) not available for locale, disabling support.")
endif (ICU_FOUND AND ICU_I18N_FOUND)
 
if (WIN32)
  add_definitions (-DBOOST_LOCALE_NO_POSIX_BACKEND=1)
  set (WIN32_SOURCES win32/collate.cpp win32/converter.cpp win32/lcid.cpp
       win32/numeric.cpp win32/win_backend.cpp )
else (WIN32)
  add_definitions (-DBOOST_LOCALE_NO_WINAPI_BACKEND=1)
endif (WIN32)

add_definitions (-DBOOST_THREAD_NO_LIB=1)
boost_add_library (
  locale
  encoding/codepage.cpp
  shared/date_time.cpp
  shared/format.cpp
  shared/formatting.cpp
  shared/generator.cpp
  shared/ids.cpp
  shared/localization_backend.cpp
  shared/message.cpp
  shared/mo_lambda.cpp

  util/codecvt_converter.cpp
  util/default_locale.cpp
  util/info.cpp
  util/locale_data.cpp
  util/gregorian.cpp

  std/codecvt.cpp
  std/collate.cpp
  std/converter.cpp
  std/numeric.cpp
  std/std_backend.cpp

  posix/codecvt.cpp
  posix/collate.cpp
  posix/converter.cpp
  posix/numeric.cpp
  posix/posix_backend.cpp

  ${WIN32_SOURCES}
  ${ICU_SOURCES}

  DEPENDS ${ICU_DEPENDS}
  LINK_LIBS ${BOOST_LOCALE_ICU_LIBRARIES}
  SHARED_COMPILE_FLAGS -DBOOST_LOCALE_DYN_LINK=1
  ${NO_STATIC_IF_ICU_FOUND}
)

