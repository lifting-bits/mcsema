#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdlib.h>

typedef int(*func_ptr)(const char*);

static int say_hello(const char* msg) {
    MessageBoxA(NULL, msg, "I'm in a thread, called by function pointer", MB_OK);
    return 42;
}

static int say_goodbye(const char* msg) {
    MessageBoxA(NULL, msg, "I'm in a thread, called by function pointer also", MB_OK);
    return 42;
}


func_ptr global_p = say_hello;

static int call_ptr_reg(int bar)
{
  int retval;
  const char pointer[] = "I'm called via register!";

  register func_ptr p = say_hello;
  if (bar == 100) {
    p = say_goodbye;
  }

  retval = p(pointer);
  return retval;
}

static int call_ptr_mem(int bar)
{
  int retval;
  const char pointer[] = "I'm called via memory!";

  retval = global_p(pointer);
  return retval;
}

__declspec(dllexport) int call_ptrs(int foo)
{
    int r1,r2,r3;
    r1 = call_ptr_reg(foo);
    r2 = call_ptr_mem(foo);
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
    rv = call_ptrs(0);
    wsprintf(msg, "Return value is: %d\n", rv);
    MessageBoxA(NULL, msg, msg, MB_OK);
    return TRUE;
}


