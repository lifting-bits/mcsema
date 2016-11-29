#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <string.h>


__declspec(dllimport) BYTE fortytwo;

__declspec(dllexport) DWORD get_value()
{
    return fortytwo;
}

BOOL APIENTRY _DllMainCRTStartup( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
                     )
{
    return TRUE;
}


