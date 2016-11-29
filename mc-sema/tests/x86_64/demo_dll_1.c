#include <windows.h>

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
                     )
{
    return TRUE;
}

 __declspec(dllexport) int HelloWorld()
{
    MessageBoxA( NULL, "Simple DLL", "I'm in a DLL", MB_OK);

    return _wtoi(L"42");
}
