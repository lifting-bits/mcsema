#include <stdlib.h>
#include <stdio.h>
#include "RegisterState.h"

extern int mcsema_main(RegState *);
extern void __mcsema_init(void);

struct Stack {
  char data[1UL << 22U];
} __attribute__((aligned(128)));

static __thread struct Stack tStack;

int httpd_driver(int argc, const char* argv[])
{
    RegState        rState;

    memset(&rState, 0, sizeof(rState));
    memset(&tStack, 0, sizeof(tStack));

    //set up the stack 
    rState.RSP = (uint64_t)(&tStack+1)-4096-8;
    rState.RDI = (uint64_t)argc;
    rState.RSI = (uint64_t)argv;
    rState.RBP = 0;
    rState.RBX = 0;
    rState.RCX = 0;

    mcsema_main(&rState);

    return rState.RAX;
}

int main(int argc, const char *argv[]) {
    __mcsema_init();
	return httpd_driver(argc, argv);
}
