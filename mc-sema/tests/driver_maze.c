#include <stdlib.h>
#include "../common/RegisterState.h"

extern int mcsema_main(RegState *);

int maze_driver(int argc, const char* argv[])
{
    RegState        rState;
    unsigned long   stack[4096*10];

    memset(&rState, 0, sizeof(rState));

    //set up the stack 
    stack[(4096*9)+1] = (uint32_t)argc;
    stack[(4096*9)+2] = (uint32_t)argv;
    rState.ESP = (unsigned long) &stack[4096*9];

    mcsema_main(&rState);

    return rState.EAX;
}

int main(int argc, const char *argv[]) {
	return maze_driver(argc, argv);
}
