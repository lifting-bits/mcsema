#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

uint64_t global_u64 = 0x3133731337ULL;
uint32_t global_u32 = 0x31337;
uint16_t global_u16 = 0x1337;
uint8_t  global_u8  = 0x37;


static void dump_globals() {
  printf("\t0x%" PRIx64 "\n", global_u64);
  printf("\t0x%" PRIx32 "\n", global_u32);
  printf("\t0x%" PRIx16 "\n", global_u16);
  printf("\t0x%" PRIx8  "\n", global_u8);
}


int main(int argc, const char *argv[]) {

  printf("Globals lists before modifiction:\n");
  dump_globals();

  if(argc % 2 == 0) {
    printf("Not adding to global variable\n");
  } else {
    global_u64 += argc;
    global_u32 += argc;
    global_u16 += argc;
    global_u8  += argc;
  }

  printf("Globals lists after modifiction:\n");
  dump_globals();

  return 0;

}
