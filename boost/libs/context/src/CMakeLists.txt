#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
add_definitions (-DBOOST_CONTEXT_NO_LIB=1)

boost_add_library (context
  fcontext.cpp
  guarded_stack_allocator_posix.cpp
  utils_posix.cpp

  NO_STATIC 
  SHARED_COMPILE_FLAGS "-DBOOST_CONTEXT_DYN_LINK=1"
  )

