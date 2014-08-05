#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdlib.h>

BOOL APIENTRY _DllMainCRTStartup( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
                     )
{
    return TRUE;
}

__declspec(dllexport) int WINAPI HelloThread(LPVOID *ptr) 
{

    MessageBoxA(NULL, (LPCSTR)ptr, "I'm a the title", MB_OK);
    free(ptr);
    return 0;

}

 __declspec(dllexport) HANDLE StartThread()
{

    DWORD tid;
    HANDLE hThread;
    const char msg[] = "I'm passed via thread parameter";
    char *foo = malloc(strlen(msg));
    strcpy(foo, msg);
    

    hThread = CreateThread(NULL,
                 0,
                 HelloThread,
                 (LPVOID)foo,
                 0,
                 &tid); 
    
    if(hThread != NULL) {
        return hThread;
    }

    return NULL;
}
