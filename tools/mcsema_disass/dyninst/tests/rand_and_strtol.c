#include <stdlib.h>
#include <stdio.h>

int main (void)
{
    int x = -11;
    int y = abs (x);

    printf ("11 : %i\n", y);

    srand (13);

    int i = rand ();
    printf ("rand: %i\n", i);

    char str [30] = "2030300 This is a test";
    char *ptr;
    long ret;

    printf ("str: \"%s\"\n", str);
    ret = strtol (str, &ptr, 10);
    printf ("Number: %ld\n", ret);
    printf ("Remainder: \"%s\"\n", ptr);

    return 0;
}
