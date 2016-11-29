#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

extern HANDLE StartServer(void);

//int WINAPI printString(const char *s, int d0, const char *s2, int d1) {
//    printf("%s | %08x | %s | %08x\n", s, d0, s2, d1);
//    return 0x80;
//}
//
//int WINAPI printInt(int i, const char *s0, int d0, const char *s1) {
//    printf("%08x | %s | %08x | %s\n", i, s0, d0, s1);
//    return 0x20;
//}

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
