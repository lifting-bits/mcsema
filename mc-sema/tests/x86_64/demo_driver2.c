#include <stdlib.h>
#include <stdio.h>
#include "../../common/RegisterState.h"

extern void demo2_entry(RegState *);

int doDemo2(int k) {
    RegState            rState = {0};
    unsigned long   stack[4096*10];

    //set up the stack 
    rState.RSP = (uint64_t) &stack[4096*9];
    rState.RAX = k;

    demo2_entry(&rState);

    return rState.RAX;
}

int main(int argc, char *argv[]) {

    int k = doDemo2(8);

    printf("0x%X\n", k);

    return 0;
}
