#include <boost/python/module.hpp>
#include <boost/preprocessor/expand.hpp>
#include <boost/preprocessor/stringize.hpp>
#include <iostream>

#ifdef NDEBUG
#define RELEASE "RELEASE"
#else
#define RELEASE "DEBUG"
#endif

#define MODNAME_THUNK() (MODNAME)

BOOST_PP_EXPAND(BOOST_PYTHON_MODULE MODNAME_THUNK())
{
  std::cout << RELEASE << " " << BOOST_PP_STRINGIZE(FLAGS) << "\n";
}
