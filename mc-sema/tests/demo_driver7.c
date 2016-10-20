#include <stdio.h>

extern int checkFn(char *);

int main(int argc, char *argv[]) {

    int i = checkFn("bar");
    int k = checkFn("foo");
    int j = checkFn("foobar");

    printf("i == %d\nk == %d\nj == %d\n", i, k, j);

    return 0;
}
