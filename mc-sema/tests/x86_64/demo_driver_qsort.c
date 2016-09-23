#include <stdlib.h>
#include "../../common/RegisterState.h"

extern int qsort_entry(RegState *);
extern void* __mcsema_create_alt_stack(size_t stack_size);
extern void* __mcsema_free_alt_stack(size_t stack_size);

__thread RegState        rState;

int qsort_driver(const char* words)
{
    uint64_t        stack[4096*10];

    memset(&rState, 0, sizeof(rState));
    __mcsema_create_alt_stack(4096*2);

    //set up the stack 
    stack[(4096*9)+0] = 0;
    stack[(4096*9)+1] = 0;
    rState.RSP = (uint64_t) &stack[4096*9];
    rState.RDI = (uint64_t)words;
    rState.RSI = 0;
    rState.RBP = 0;
    rState.RBX = 0;
    rState.RCX = 0;
    rState.RAX = 31337;

    qsort_entry(&rState);
    __mcsema_free_alt_stack(4096*2);

    return rState.RAX;
}

int main(int argc, const char *argv[]) {
	return qsort_driver("Sorted numbers:");
}
