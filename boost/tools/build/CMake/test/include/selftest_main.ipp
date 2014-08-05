#include <selftest_report.hpp>
#include <string>
#include <iostream>

int main(int argc, char** argv)
{
  std::cout << libname() << "-" 
	    << shared_or_static() << "_" 
	    << debug_or_release() << "_"
	    << single_or_multi() << "\n";
}
