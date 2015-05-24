#include <stdio.h>
#include <string.h>
#define TARGET_IA64
#include "../../common/RegisterState.h"

extern void demo1_entry(RegState *);

unsigned long getNextPC(void) {
    return 0;
}

int doDemo1(int k) {
    RegState        rState;
    unsigned long   stack[4096*10];

    memset(&rState, 0, sizeof(rState));

    //set up the stack 
    rState.RSP = (unsigned long) &stack[4096*9];
    rState.RAX = k;

    demo1_entry(&rState);

    return rState.RAX;
}

int main(int argc, char *argv[]) {

    int k = doDemo1(12);

    printf("0x%X -> 0x%X\n", 12, k);

    return 0;
}
