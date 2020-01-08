#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

union ufoo {
  uint64_t u64;
  uint32_t u32;
  uint16_t u16;
  uint8_t   u8; 
  uint8_t  bytes[8];
};


union ufoo global_ufoo;


static void dump_union(union ufoo *f) {

  printf("\t0x%" PRIx64 "\n", f->u64);
  printf("\t0x%" PRIx32 "\n", f->u32);
  printf("\t0x%" PRIx16 "\n", f->u16);
  printf("\t0x%" PRIx8  "\n", f->u8);
  printf("\t");
  for(int i = 0; i < 8; i++ ) {
    printf("0x%"PRIx8 " ", f->bytes[i]);
  }
  printf("\n");
}


int main(int argc, const char *argv[]) {

  printf("Union before modifiction:\n");
  memset(&global_ufoo, 0, sizeof(global_ufoo));

  dump_union(&global_ufoo);

  if(argc % 2 == 0) {
    printf("Not adding to variables\n");
  } else {
    global_ufoo.u64 += argc;
    global_ufoo.u32 += argc;
    global_ufoo.u16 += argc;
    global_ufoo.u8  += argc;
  }

  printf("Union after modifiction:\n");
  dump_union(&global_ufoo);

  return 0;

}
