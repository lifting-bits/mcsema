#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdlib.h>

typedef int(__stdcall *func_ptr)(const char*);

static int _stdcall say_hello(const char* msg) {
    MessageBoxA(NULL, msg, "I'm in a thread, called by function pointer", MB_OK);
    return 42;
}


static int call_ptr_reg()
{

    const char pointer[] = "I'm called via register!";

    func_ptr p = say_hello;
    int retval;

    _asm {
        lea EAX, dword ptr pointer
        PUSH eax
        MOV eax, p
        CALL eax
        add esp, 4
        MOV retval, eax
        }

    return retval;
}

static int call_ptr_mem()
{
    const char pointer[] = "I'm called via memory!";

    func_ptr p = say_hello;
    int retval;

    _asm {
        lea EAX, dword ptr pointer
        PUSH eax
        CALL dword ptr [p]
        MOV retval, eax
        }

    return retval;
}

__declspec(dllexport) int call_ptrs()
{
    int r1,r2,r3;
    r1 = call_ptr_reg();
    r2 = call_ptr_mem();
    r3 = 0x1;

    return r1+r2+(31337-42-42);
}

BOOL APIENTRY _DllMainCRTStartup( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
                     )
{
    char msg[128];
    int rv;
    rv = call_ptrs();
    wsprintf(msg, "Return value is: %d\n", rv);
    MessageBoxA(NULL, msg, msg, MB_OK);
    return TRUE;
}


