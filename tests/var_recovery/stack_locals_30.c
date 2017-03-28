#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LEN 16

typedef struct _blob {
    int len;
    char str[LEN];
} blob;

int xor(char c, blob *in, blob *out)
{
    int i;
    for(i = 0; i < c && i < in->len && i < LEN; i++)
    {
        out->str[i] = in->str[i] ^ c;
    }
    out->len = i;

    return i;
}

int main(int argc, char **argv)
{
    int a, i;
    char r;
    blob input = {0};
    blob output = {0};
    
    srand(time(NULL));

    for(i = 0; i < LEN && i < strlen(argv[0]); i++)
    {
        input.str[i] = argv[0][i];
    }
    input.len = i;
  
    for(i = 0; i < LEN; i++)
    {
        while(r == 0)
        {
            r = (char)(rand() % 0x100);
        }
        output.str[i] = r; 
    }
    output.len = LEN;

    r = (char)(rand() % 0x100);

    a = xor(r, &input, &output); 
    
    printf("input (%d bytes):\t", input.len);
    for(i = 0; i < input.len; i++)
    {
        printf("%02x ", input.str[i]);
    }
    printf("\n");
    printf("r = 0x%02x (%lu bytes)\n", r, sizeof(char));
    printf("output (%d bytes):\t", output.len);
    for(i = 0; i < output.len; i++)
    {
        printf("%02x ", output.str[i]);
    }
    printf("\n\n");

    return 0;
}   
