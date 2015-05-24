#include <stdint.h>

void shiftit(int amt, uint64_t *orig) {

    uint64_t newval = *orig;

    newval >>= amt;

    *orig = newval;
}

