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


struct foo global_foo;


static void dump_struct(struct foo *f) {

  printf("\t0x%" PRIx64 "\n", f->u64);
  printf("\t0x%" PRIx32 "\n", f->u32);
  printf("\t0x%" PRIx16 "\n", f->u16);
  printf("\t0x%" PRIx8  "\n", f->u8);
}


int main(int argc, const char *argv[]) {

  printf("Struct before modifiction:\n");
  memset(&global_foo, 0, sizeof(global_foo));

  dump_struct(&global_foo);

  if(argc % 2 == 0) {
    printf("Not adding to variables\n");
  } else {
    global_foo.u64 += argc;
    global_foo.u32 += argc;
    global_foo.u16 += argc;
    global_foo.u8  += argc;
  }

  printf("Struct after modifiction:\n");
  dump_struct(&global_foo);

  return 0;

}
