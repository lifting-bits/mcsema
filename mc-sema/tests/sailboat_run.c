#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern int keycomp(const char*);

// these are needed since we don't have libgcc
uint64_t __udivmoddi4(uint64_t num, uint64_t den, uint64_t *rem_p)
{
  uint64_t quot = 0, qbit = 1;

  if ( den == 0 ) {
    return 1/((unsigned)den); /* Intentional divide by zero, without
                                 triggering a compiler warning which
                                 would abort the build */
  }

  /* Left-justify denominator and count shift */
  while ( (int64_t)den >= 0 ) {
    den <<= 1;
    qbit <<= 1;
  }

  while ( qbit ) {
    if ( den <= num ) {
      num -= den;
      quot += qbit;
    }
    den >>= 1;
    qbit >>= 1;
  }

  if ( rem_p )
    *rem_p = num;

  return quot;
}

int64_t __divdi3(int64_t num, int64_t den)
{
  int minus = 0;
  int64_t v;

  if ( num < 0 ) {
    num = -num;
    minus = 1;
  }
  if ( den < 0 ) {
    den = -den;
    minus ^= 1;
  }

  v = __udivmoddi4(num, den, NULL);
  if ( minus )
    v = -v;

  return v;
}

uint64_t __udivdi3(uint64_t num, uint64_t den)
{
    return __udivmoddi4(num, den, NULL);
}

int64_t __moddi3(int64_t num, int64_t den)
{
  int minus = 0;
  int64_t v;

  if ( num < 0 ) {
    num = -num;
    minus = 1;
  }
  if ( den < 0 ) {
    den = -den;
  }

  (void) __udivmoddi4(num, den, (uint64_t *)&v);
  if ( minus )
    v = -v;

  return v;
}

uint64_t __umoddi3(uint64_t num, uint64_t den)
{
  uint64_t v;

  (void) __udivmoddi4(num, den, &v);
  return v;
}
  
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
