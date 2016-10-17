#include <stdio.h>
#include <string.h>
#include "../../common/RegisterState.h"

extern void sub_1(RegState *);

int doDemo1(int k) {
    RegState        rState;
    unsigned long   stack[4096*10];

    memset(&rState, 0, sizeof(rState));

    //set up the stack 
    rState.RSP = (uint64_t) &stack[4096*9];
    rState.RAX = k;

    sub_1(&rState);

    return rState.RAX;
}

int main(int argc, char *argv[]) {

    int k = doDemo1(12);

    printf("0x%X -> 0x%X\n", 12, k);

    return 0;
}
