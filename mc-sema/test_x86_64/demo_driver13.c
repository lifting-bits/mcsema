#include <stdio.h>

extern int demo13_entry(int);

int main(int argc, char *argv[]) {
    int i = 0;

    for(i = 0; i <= 255; i++) {
        demo13_entry(i);
    }

    return 0;
}
