#include <stdio.h>

extern int demo13_entry(int);
extern void* __mcsema_create_alt_stack(size_t stack_size);
extern void* __mcsema_free_alt_stack(size_t stack_size);

int main(int argc, char *argv[]) {
    __mcsema_create_alt_stack(4096*2);

    int i = 0;

    for(i = 0; i <= 255; i++) {
        demo13_entry(i);
    }

    __mcsema_free_alt_stack(4096*2);
    return 0;
}
