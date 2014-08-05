#include <stdlib.h>
#include <stdio.h>

extern int demo_dll_1_driver(void);

int main(int argc, char *argv[]) {
    printf("About to do msgbox...\n");
    demo_dll_1_driver();
    return 0;
}
