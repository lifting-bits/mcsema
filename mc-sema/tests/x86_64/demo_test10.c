#include <stdio.h>

unsigned int a = 0xAA0000;
unsigned int b = 0x00BB00;
unsigned int c = 0x0000CC;

unsigned int *mydata[] = {
    NULL,
    &a,
    NULL,
    NULL,
    &b,
    NULL,
    NULL,
    &c,
    NULL,
    NULL
};


int printdata(void) {
    int i;

    for(i = 0; 
        i < sizeof(mydata)/sizeof(mydata[0]); 
        i++) 
    {
        if(mydata[i] != NULL) {
            printf("mydata[%d] = %p => 0x%06X\n", i, mydata[i], *(mydata[i]));
        }
    }

    return 0;

}
