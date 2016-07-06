#include <stdlib.h>

extern int mcsema_main(int argc, const char *argv[]);
extern void* __mcsema_create_alt_stack(size_t stack_size);
extern void* __mcsema_free_alt_stack(size_t stack_size);

int main(int argc, const char *argv[]) {
    __mcsema_create_alt_stack(4096*2);
    int rv =  mcsema_main(argc, argv);
    __mcsema_free_alt_stack(4096*2);
    return rv;
}
