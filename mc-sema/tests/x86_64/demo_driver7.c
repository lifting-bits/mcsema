#include <stdio.h>

extern int demo7_entry(char *);

int main(int argc, char *argv[]) {

    int i = demo7_entry("bar");
    int k = demo7_entry("foo");
    int j = demo7_entry("foobar");

    printf("i == %d\nk == %d\nj == %d\n", i, k, j);

    return 0;
}
