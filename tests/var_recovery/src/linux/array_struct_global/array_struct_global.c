#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

struct foo {
  uint64_t u64;
  uint32_t u32;
  uint16_t u16;
  uint8_t   u8; 
};


struct foo global_foos[64];


static void dump_struct(struct foo foos[64]) {

  for(int i = 0; i < 64; i++) {
    printf("\t0x%" PRIx64 "\n", foos[i].u64);
    printf("\t0x%" PRIx32 "\n", foos[i].u32);
    printf("\t0x%" PRIx16 "\n", foos[i].u16);
    printf("\t0x%" PRIx8  "\n", foos[i].u8);
  }

}


int main(int argc, const char *argv[]) {

  printf("Array of struct before modifiction:\n");
  memset(&global_foos, 0, sizeof(global_foos));

  dump_struct(global_foos);

  if(argc % 2 == 0) {
    printf("Not adding to variables\n");
  } else {
    for(int i = 0; i < 64; i ++ ) {
      global_foos[i].u64 += argc + i;
      global_foos[i].u32 += argc + i;
      global_foos[i].u16 += argc + i;
      global_foos[i].u8  += argc + i;
    }
  }

  printf("Array of struct after modifiction:\n");
  dump_struct(global_foos);

  return 0;

}
