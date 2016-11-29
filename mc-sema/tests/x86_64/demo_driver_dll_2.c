#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

extern HANDLE StartThread(void);

int main(int argc, char *argv[]) {
    HANDLE hThread;
    DWORD dwRet;

    printf("About to do msgbox via thread...\n");
    hThread = StartThread();
    printf("Created thead: %p\n", hThread);

    printf("Waiting for 10 sec for msgbox...\n");
    dwRet = WaitForSingleObject(hThread, 10000);
    if(dwRet != WAIT_OBJECT_0) {
        printf("Wait failed. This is not bad if there is a message box. \n");  	 
    } else {
        printf("Wait succeeded!\n");
    }

    return 0;
}
