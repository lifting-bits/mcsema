#undef UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>

__declspec(dllexport) BYTE fortytwo = 42;

BOOL APIENTRY _DllMainCRTStartup( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
                     )
{
    return TRUE;
}


