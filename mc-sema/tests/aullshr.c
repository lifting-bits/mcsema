#include <stdint.h>
#include "../common/RegisterState.h"

void __mcsema___aullshr(RegState *r)
{ 
    unsigned short cl = (r->ECX) & 0xFF;
    uint64_t edxeax = 
        ((uint64_t)(r->EDX) << 32) | 
        (uint64_t)(r->EAX);
    // this will *probably* emit another aullshr, but we can link against this version
    edxeax >>= cl;
    r->EAX = (uint32_t)(edxeax & 0xFFFFFFFFULL);
    r->EDX = (uint32_t)(edxeax >> 32);
    // simulate the 'ret'
    r->ESP = r->ESP + 4;
}
