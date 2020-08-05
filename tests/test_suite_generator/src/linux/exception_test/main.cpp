#include <stdlib.h>
#include <cstdio>
#include <stdexcept>
#include <string>

using namespace std;

void test_throw_double() { throw 4.3; }

void test_throw_out_of_range() {
  printf("  Throwing out_of_range()\n");
  throw out_of_range("out_of_range comment");
}

void test_throw_runtime_error() {
  printf("  Throwing runtime_error()\n");
  throw runtime_error("runtime_error comment");
}

unsigned int num_tests;
int main(int argc, char *argv[]) {
  int p = 0;
  try {
    if (argc > 1) {
      int input = atoi(argv[1]);
      if (input == 1) {
        test_throw_out_of_range();
      } else if (input == 2) {
        test_throw_double();
      } else if (input == 3) {
        test_throw_runtime_error();
      }
    } else {
      printf("Fallback mode, Not throwing exception\n");
    }
  } catch (double smess) {
    p = p + 2;
    printf("Catching: double\n");
  } catch (out_of_range orex) {
    p = p + 4;
    printf("Catching: out_of_range %s\n", orex.what());
  } catch (runtime_error rex) {
    p = p + 6;
    printf("Catching: runtime_error %s\n", rex.what());
  }

  printf("Throw test finished! %d\n", p);
  return 0;
}
