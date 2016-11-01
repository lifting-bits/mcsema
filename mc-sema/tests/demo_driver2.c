#include <stdlib.h>
#include <stdio.h>
#include "../common/RegisterState.h"

#ifdef _WIN32
extern void sub_1(RegState *);
void sub_8000001(RegState *r) { sub_1(r); }
#else
extern void sub_8000001(RegState *);
#endif

int doDemo2(int k) {
    RegState            rState = {0};
    unsigned long   stack[4096*10];

    //set up the stack 
    rState.ESP = (uint32_t) &stack[4096*9];
    rState.EAX = k;

    sub_8000001(&rState);

    return rState.EAX;
}

int main(int argc, char *argv[]) {

    int k = doDemo2(8);

    printf("0x%X\n", k);

    return 0;
}
