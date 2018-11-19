#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

uint64_t global_u64 = 0x31337;


int main(int argc, const char *argv[]) {

  if(argc % 2 == 0) {
    printf("Not adding to global variable\n");
  } else {
    global_u64 += argc;
  }

  printf("Global is: 0x%" PRIx64 "\n", global_u64);

  return 0;

}
