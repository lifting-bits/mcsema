#include <stdio.h>
#include <string.h>
#include <immintrin.h>
#include <mmintrin.h>
#include "../../common/RegisterState.h"

extern void demo_fpu1_entry(RegState *);

long double DoDemoFpu1(long double k) {
    __m128d foo;
    RegState            rState = {0};
    unsigned long   stack[4096*10];
    xmmregstate n;

    rState.RSP = (uint64_t) &stack[0x8ff4];
    foo = _mm_loadu_pd(&k);
    memcpy(rState.XMM0.tag, &foo, sizeof(foo)); 

    demo_fpu1_entry(&rState);
    long double bar;
    _mm_store_pd(&bar, *(__m128d*)(&rState.XMM0.tag));
    //return NATIVEFPU_TO_LD((nativefpu*)(rState.XMM0.tag));
    return bar;
}

int main(int argc, char *argv[]) {

    long double n = 2.0;
    long double k = DoDemoFpu1(n);

    //  msvcrt only has 64-bit double, not 96-bit long double
    //  http://stackoverflow.com/questions/7134547/gcc-printf-and-long-double-leads-to-wrong-output-c-type-conversion-messes-u
#ifdef _WIN32
    printf("%0.16Lf -> %0.16Lf\n", (double)n, (double)k);
#else
    printf("%0.16Lf -> %0.16Lf\n", n, k);
#endif

    return 0;
}
