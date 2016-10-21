#include <stdio.h>

#ifdef linux
#define __fastcall __attribute__((fastcall))
#define __cdecl __attribute__((cdecl))
#define __stdcall __attribute__((stdcall))
#endif

//int __fastcall imfastcall(int a1, int a2) {
//    printf("fastcall args are: %08x, %08x\n", a1, a2);
//    return a1+a2;
//}

int __stdcall imstdcall(int a1, int a2) {
    //printf("stdcall args are: %08x, %08x\n", a1, a2);
    return a1+a2;
}

//int __cdecl imcdecl(int a1, int a2) {
//    printf("cdecl args are: %08x, %08x\n", a1, a2);
//    return a1+a2;
//}
