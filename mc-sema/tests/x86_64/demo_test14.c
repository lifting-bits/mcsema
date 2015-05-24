#ifdef linux
#define __fastcall __attribute__((fastcall))
#endif

extern int __fastcall threeArgs(int a1, int a2, int a3);
extern int __fastcall twoArgs(int a1, int a2);
extern int __fastcall oneArg(int a1);

int printMessages(void) {
    int ret = 0;
    ret = threeArgs(0x100, 0x200, 0x300);
    if(ret != 42) {
        return -1;
    }
    ret = twoArgs(0x400, 0x500);
    if(ret != 42) {
        return -2;
    }
    ret = oneArg(0x600);
    if(ret != 42) {
        return -3;
    }

    return 0;
}
