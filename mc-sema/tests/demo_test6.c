#ifdef WIN32
#include <windows.h>
#else
#include <string.h>
#include <stdlib.h>
#endif

void foo(void) {
    return;
}

static int checkFn(char *f) {
    int r = 1;
    int k = strlen(f);

    if( k > 1 ) {
        char a = f[0];
        char b = f[k-1];

        if( a == b ) {
            r = 0;
        }
    }

    return r;
}

static void doStuff(char *src, char *dst) {
    
    char *s1 = src;
    char *d1 = dst;

    char c1 = *s1;
    while( c1 != 0 ) {

        if( c1 == '/' ) {
            *d1 = '\\';
        } else {
            *d1 = c1;
        }

        ++s1;
        ++d1;
        c1 = *s1;
    }

    return;
}

void doWork(char **f, int l) {
    int a = 0;
    char* b = malloc(l*sizeof(char*));
    for( ; a < l; a++ ) {
        char *c = f[a];
        if( checkFn(c) == 0 ) {
            doStuff(c, c);
        }
    }
    b[1] = 2;

    return;
}
