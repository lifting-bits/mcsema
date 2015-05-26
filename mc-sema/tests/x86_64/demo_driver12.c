#include <stdlib.h>
#include <stdio.h>
#define TARGET_IA64
#include "../../common/RegisterState.h"

extern void demo12_entry(RegState *);

int doDemo12(int k) {
    RegState            rState = {0};
    unsigned long   stack[4096*10];

    //set up the stack 
    rState.RSP = (unsigned long) &stack[4096*9];
    rState.RAX = k;

    demo12_entry(&rState);

    return rState.RAX;
}

int main(int argc, char *argv[]) {

    int k = doDemo12(8);

    printf("0x%X\n", k);

    return 0;
}
