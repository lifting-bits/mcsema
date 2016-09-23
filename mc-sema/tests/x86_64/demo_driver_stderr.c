#include <stdlib.h>
#include "../../common/RegisterState.h"

extern int stderr_entry(RegState *);

int stderr_driver(const char* words)
{
    RegState        rState;
    uint64_t        stack[4096*10];

    memset(&rState, 0, sizeof(rState));

    //set up the stack 
    stack[(4096*9)+0] = 0;
    stack[(4096*9)+1] = 0;
    rState.RSP = (uint64_t) &stack[4096*9];
    rState.RDI = (uint64_t)words;
    rState.RSI = 0;
    rState.RBP = 0;
    rState.RBX = 0;
    rState.RCX = 0;

    stderr_entry(&rState);

    return rState.RAX;
}

int main(int argc, const char *argv[]) {
	return stderr_driver("this is output on stderr");
}
