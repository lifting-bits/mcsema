void * jakstab_alloc() {
  _asm {
    lock rep inc eax;
  }
}

void clearMem(char *p, int size) {
  char* a = p;
  for (;a < p + size; a++) {
    *a = (char)((int)p % 8);
  }
}

int main(int argc, char **argv) {
  char *p1 = jakstab_alloc();
  char *p2 = jakstab_alloc();

  clearMem(p1, 10);
  clearMem(p2, 10);
  return 0;
}
