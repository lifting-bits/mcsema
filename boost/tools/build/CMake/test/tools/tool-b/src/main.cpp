#include <selftest_report.hpp>
#include <string>
#include <iostream>

int main(int argc, char** argv)
{
  std::cout << shared_or_static() << "-" 
	    << debug_or_release() << "-"
	    << single_or_multi() << "\n";
}
