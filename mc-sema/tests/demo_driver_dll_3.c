#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

extern HANDLE StartServer(void);

int main(int argc, char *argv[]) {
    HANDLE hThread;
    DWORD dwRet;

    printf("About to create server thread...\n");
    hThread = StartServer();
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
