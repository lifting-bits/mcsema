#include <stdio.h>
#include <string.h>
#include "../common/RegisterState.h"

#ifdef _WIN32
extern void sub_1(RegState *);
void sub_8000001(RegState *r) { sub_1(r); }
#else
extern void sub_8000001(RegState *);
#endif

int doDemo1(int k) {
    RegState        rState;
    unsigned long   stack[4096*10];

    memset(&rState, 0, sizeof(rState));

    //set up the stack 
    rState.ESP = (uint64_t) &stack[4096*9];
    rState.EAX = k;

    sub_8000001(&rState);

    return rState.EAX;
}

int main(int argc, char *argv[]) {

    int k = doDemo1(12);

    printf("0x%X -> 0x%X\n", 12, k);

    return 0;
}
