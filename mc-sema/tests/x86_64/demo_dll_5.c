#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <string.h>


char spartacus[256];

__declspec(dllexport) const char* get_response(void) {
    return spartacus;
}
__declspec(dllexport) const char* who_is_spartacus2(void)
{
    return strcpy(spartacus, "No, I am Spartacus!");
}

__declspec(dllexport) const char* who_is_spartacus(void)
{
    return strcpy(spartacus, "I am Spartacus");
}

BOOL APIENTRY _DllMainCRTStartup( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
                     )
{
    return TRUE;
}


