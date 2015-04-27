#ifdef WIN32
#include <windows.h>
#include <string.h>
#else
#include <stdlib.h>
#include <string.h>
#define CHAR char
#endif

int foo(int a) { return a+1; }

CHAR *doTrans(CHAR *inS) {
    size_t  oldS = strlen(inS)+sizeof(CHAR);
#ifdef WIN32
    CHAR    *newS = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, oldS);
#else
    CHAR    *newS = malloc(oldS);
#endif

    if( newS ) {
        CHAR    *curP = inS;
        CHAR    *curN = newS;
       
        memset(newS, 0, oldS);

        while( *curP != 0 ) {
            if( *curP == '/' ) {
                *curN = '\\';
            } else {
                *curN = *curP;
            }

            ++curP;
            ++curN;
        }

        return newS;
    } else {
        return NULL;
    }
}
