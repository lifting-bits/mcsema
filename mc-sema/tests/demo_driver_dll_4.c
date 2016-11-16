#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

extern DWORD call_ptrs(void);

int main(int argc, char *argv[]) {
    DWORD dwRet;

    printf("About to call a function pointer...\n");
    dwRet = call_ptrs();
    printf("Function returned: %d\n", dwRet);

    return 0;
}
