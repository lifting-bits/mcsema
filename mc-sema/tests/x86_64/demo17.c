#include <stdio.h>

typedef int (*callback)(int a1, int a2, int a3, int a4, int a5, int a6);

int f1(int a1, int a2, int a3, int a4, int a5, int a6) {
    printf("in f1: %08x, %08x, %08x, %08x, %08x, %08x\n", a1, a2, a3, a4, a5, a6);
    return 1;
}

int f2(int a1, int a2, int a3, int a4, int a5, int a6) {
    int p  = printf("in f2: %08x, %08x, %08x, %08x, %08x, %08x\n", a1, a2, a3, a4, a5, a6);
    callback c2 = NULL;

    //// ensure assignment to variable is not optimized out
    if(p == 0x10001) {
        c2 = f2;
    } else {
        // should always go here
        c2 = f1;
    }
    //
    //// invokes recursive do_call_value in mcsema
    c2(a1, a2, a3, a4, a5, a6);
    puts("done with c2");
    printf("done with f1: %08x,\n", a1);
    return 2;
}

int main(int argc, const char* argv[]) {

    callback c = NULL;

    // try to always call c2 but prevent the compiler from optimizing the callback
    int a1 = 0x100, a2 = 0x200, a3 = 0x300, a4 = 0x400, a5 = 0x500, a6 = 0x600;
    if(argc > 100) {
        c = f1;
    } else {
        c = f2;
    }

    c(a1, a2, a3, a4, a5, a6);
    printf("done with c: %08x, %08x, %08x, %08x, %08x, %08x\n", a1, a2, a3, a4, a5, a6);
    
    return 0;
}
