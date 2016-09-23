#include <stdio.h>

typedef int (*callback)(void);

int f1(void) {
    printf("in f1\n");
    return 1;
}

int f2(void) {
    int p = printf("in f2\n");
    callback c2 = NULL;

    // ensure assignment to variable is not optimized out
    if(p == 0x10001) {
        c2 = f2;
    } else {
        // should always go here
        c2 = f1;
    }
    
    // invokes recursive do_call_value in mcsema
    c2();
    return 2;
}

int main(int argc, const char* argv[]) {

    callback c = NULL;

    // try to always call c2 but prevent the compiler from optimizing the callback
    if(argc > 100) {
        c = f1;
    } else {
        c = f2;
    }

    c();
    
    return 0;
}
