#include <stdio.h>

int print_it(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    return 0;
}
