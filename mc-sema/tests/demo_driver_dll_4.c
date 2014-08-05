#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

extern DWORD demo_dll_4_driver(void);

int main(int argc, char *argv[]) {
    DWORD dwRet;

    printf("About to call a function pointer...\n");
    dwRet = demo_dll_4_driver();
    printf("Function returned: %d\n", dwRet);

    return 0;
}
