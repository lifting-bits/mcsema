#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern int keycomp(const char*);
  
uint32_t to_byte(uint8_t b) {
    if(b <= '9') {return b - '0';}
    if(b <= 'F') {return b - '7';}
    if(b <= 'f') {return b - 'W';}

    return 0;
}

uint32_t read_bytes(uint32_t base, const char *p, int l)
{
    int i;
    for(i = 0; i < l; i++)
    {
        base <<= 4;
        base |= to_byte(p[i]);
    }

    return base;
}

int main(int argc, char *argv[]) {
    char *key;
    int ret;
    if(argc < 2)
    {
        fprintf(stderr, "give me a key in the format key{hex}\n");
        return -1;
    }

    key = argv[1]; //"key{d9dd1cb9dc13ebc3dc3780d76123ee34}";
    ret = keycomp(key);
    if(ret == 0) {
        printf("a winner is you!\n");
    } else {
        printf("set sail for fail: %d\n",ret );
    }

    return ret;
}
