#include <stdio.h>

#ifdef linux
#define __fastcall __attribute__((fastcall))
#endif

extern int printMessages(void);

int __fastcall threeArgs(int a1, int a2, int a3) {
    printf("Three arg fastcall: %08x, %08x, %08x\n", a1, a2, a3);
    return 42;
}

int __fastcall twoArgs(int a1, int a2) {
    printf("Two arg fastcall: %08x, %08x\n", a1, a2);
    return 42;
}

int __fastcall oneArg(int a1) {
    printf("One arg fastcall: %08x\n", a1);
    return 42;
}

int main(int argc, char *argv[]) {
    int ret;
    ret = printMessages();
    if(0 != ret) {
        printf("Failed: %d\n", ret);
    }
    return 0;
}
