#include <unistd.h>
#include <stdlib.h>

static char someglobal = 1;

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

    return 0;
}
