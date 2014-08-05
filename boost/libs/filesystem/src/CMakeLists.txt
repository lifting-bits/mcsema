#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
boost_add_library (filesystem
  codecvt_error_category.cpp operations.cpp path.cpp path_traits.cpp
  portability.cpp unique_path.cpp utf8_codecvt_facet.cpp
  windows_file_codecvt.cpp
  SHARED_COMPILE_FLAGS "-DBOOST_FILESYSTEM_DYN_LINK=1"
  STATIC_COMPILE_FLAGS "-DBOOST_FILESYSTEM_STATIC_LINK=1"
  DEPENDS boost_system
)

