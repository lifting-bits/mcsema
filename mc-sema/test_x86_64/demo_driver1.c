#include <stdio.h>
#include <string.h>

#include "../common/RegisterState.h"

extern void demo1_entry(RegState *);

unsigned long getNextPC(void) {
    return 0;
}

int doDemo1(int k) {
    RegState        rState;
    unsigned long   stack[4096*10];

    memset(&rState, 0, sizeof(rState));

    //set up the stack 
    rState.ESP = (unsigned long) &stack[4096*9];
    rState.EAX = k;

    demo1_entry(&rState);

    return rState.EAX;
}

int main(int argc, char *argv[]) {

    int k = doDemo1(12);

    printf("0x%X -> 0x%X\n", 12, k);

    return 0;
}
