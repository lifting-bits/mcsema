#include <assert.h>
#include <z3.h>
int main() {
  unsigned int major, minor, build, rev;
  Z3_get_version(&major, &minor, &build, &rev);
  printf("%u.%u.%u", major, minor, build);
  return 0;
}
