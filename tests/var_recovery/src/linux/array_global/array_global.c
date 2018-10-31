#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>



uint64_t global_array[64];

static void dump_array(uint64_t global_array[64]) {

  for(int i = 0; i < 64; i++) {
    if(i % 8 == 0) {
      printf("\n");
    }
    printf("\t0x%" PRIx64, global_array[i]);
  }

  printf("\n");

}


int main(int argc, const char *argv[]) {

  printf("Array before modifiction:\n");
  memset(&global_array, 0, sizeof(global_array));

  dump_array(global_array);

  if(argc % 2 == 0) {
    printf("Not adding to variables\n");
  } else {

    if(argc <= 0) {
      argc = 1;
    }

    for(int i = 0; i < 64; i += argc) {
      global_array[i] += argc;
    }
  }

  printf("Array after modifiction:\n");
  dump_array(global_array);

  return 0;

}
