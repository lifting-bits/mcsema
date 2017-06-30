#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>

int main(int argc, char **args)
{
    uint8_t fold = 0xAF;
    void (*obf_funcs[]) (void) = {
        (void (*) (void))main,
        (void (*) (void))main,
        (void (*) (void))main,
        (void (*) (void))main,
        (void (*) (void))main,
        (void (*) (void))main,
        (void (*) (void))main,
        (void (*) (void))main,
        (void (*) (void))main,
    };

    printf("hrm: %zu\n", sizeof (obf_funcs));
    printf("hrm: %zu\n", sizeof (void *));
    printf("div: %zu\n", (sizeof (obf_funcs) / sizeof (void *)));
    fold %= (sizeof (obf_funcs) / sizeof (void *));
    printf("so answer: %d\n", fold);
    return 0;
}
