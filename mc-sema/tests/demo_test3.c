int foo(int a) { return a+1; }

void demo3(char *src, char *dst) {
    
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
