#include <boost/preprocessor/stringize.hpp>
#include <string>
#include <iostream>

int main(int argc, char** argv)
{
  std::cout << BOOST_PP_STRINGIZE(LIBNAME) << "-" 
	    << BOOST_PP_STRINGIZE(TOPLEVEL_SHARED_OR_STATIC) << "_" 
	    << BOOST_PP_STRINGIZE(TOPLEVEL_DEBUG_OR_RELEASE) << "_" 
	    << BOOST_PP_STRINGIZE(TOPLEVEL_MULTI_OR_SINGLE) 
	    << "\n";
}
