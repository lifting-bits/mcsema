#----------------------------------------------------------------------------
# CMake framework maintained by Denis Arnaud on git://github.com/pocb/boost
#----------------------------------------------------------------------------
#
add_definitions (-DBOOST_DATE_TIME_DYN_LINK=1 -DDATE_TIME_INLINE)
boost_add_library (
  date_time
  gregorian/greg_month.cpp
  gregorian/greg_weekday.cpp
  gregorian/date_generators.cpp 
  
  STATIC_COMPILE_FLAGS -DBOOST_DATE_TIME_STATIC_LINK
  SHARED_COMPILE_FLAGS -DBOOST_ALL_DYN_LINK=1
  )
