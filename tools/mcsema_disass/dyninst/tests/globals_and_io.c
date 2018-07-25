#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

static char someglobal = 1;
static int gInt[2] = {42, 43};

int writeit()
{
    write(2,&someglobal,1);
    someglobal++;
    write(2,&someglobal,1);
    return 0;
}

int main(void)
{
    someglobal = 0x68;
    writeit();
    gInt[1] = 44;
    printf("\n");
    printf("%i, %i\n", gInt[0], gInt[1]);
    return 0;
}
