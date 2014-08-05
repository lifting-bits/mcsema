#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

extern HANDLE demo_dll_3_driver(void);

int main(int argc, char *argv[]) {
    HANDLE hThread;
    DWORD dwRet;

    printf("About to create server thread...\n");
    hThread = demo_dll_3_driver();
    printf("Created thead: %p\n", hThread);

    printf("Waiting for server thread to terminate...\n");
    dwRet = WaitForSingleObject(hThread, INFINITE);
    if(dwRet != WAIT_OBJECT_0) {
        printf("WaitForSingleObject terminated terminated\n");
    } else {
        printf("Thread finished!\n");
    }

    return 0;
}
