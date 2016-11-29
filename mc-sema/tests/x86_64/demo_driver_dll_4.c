#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

extern DWORD call_ptrs(int);

int main(int argc, char *argv[]) {
    DWORD dwRet;

    printf("About to call a function pointer...\n");
    dwRet = call_ptrs(0);
    printf("Function returned: %lu\n", dwRet);

    return 0;
}
