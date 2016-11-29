#include <stdio.h>
#include <string.h>
#include <immintrin.h>
#include <mmintrin.h>

extern long double timespi(long double k);

#ifdef __linux__
long double DoDemoFpu1(long double k) {
    return timespi(k);
}
#else
long double DoDemoFpu1(long double k) {
    return timespi(k);
}
#endif

int main(int argc, char *argv[]) {

    long double n = 2.0;
    long double k = DoDemoFpu1(n);

    //  msvcrt only has 64-bit double, not 96-bit long double
    //  http://stackoverflow.com/questions/7134547/gcc-printf-and-long-double-leads-to-wrong-output-c-type-conversion-messes-u
#ifdef _WIN32
    printf("%0.16Lf -> %0.16Lf\n", (long double)n, (long double)k);
#else
    printf("%0.16Lf -> %0.16Lf\n", n, k);
#endif

    return 0;
}
