#include <stdio.h>

#ifdef linux
#define __fastcall __attribute__((fastcall))
#define __cdecl __attribute__((cdecl))
#define __stdcall __attribute__((stdcall))
#endif

extern int __fastcall imfastcall(int a0, int a1);
extern int __stdcall imstdcall(int a0, int a1);
extern int __cdecl imcdecl(int a0, int a1);

int main(int argc, char *argv[]) {
    int ret;

    ret = imstdcall(0x100,0x200);
    if(0x300 != ret) {
        printf("Failed stdcall: %08x", ret);
        return -1;
    }

    //ret = imfastcall(ret,0x200);
    //if(0x500 != ret) {
    //    printf("Failed fastcall: %08x", ret);
    //    return -2;
    //}

    //ret = imcdecl(0x200, ret);
    //if(0x700 != ret) {
    //    printf("Failed cdecl: %08x", ret);
    //    return -3;
    //}

    printf("Test Passed\n");
    return 0;
}
