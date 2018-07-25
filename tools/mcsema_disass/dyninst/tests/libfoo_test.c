#include <stdio.h>

extern int foo (void);
extern int bar (int);
extern int baz (void);
extern int test (int);

int main (int argc, char **argv)
{
    printf ("foo(): %d (should be: 42)\n", foo ());
    printf ("bar(15): %d (should be: 57)\n", bar (15));
    printf ("baz(): %d (should be: 51)\n", baz ());
    printf ("test(6): %d (should be: 21)\n", test(6));

    return 0;
}
