#include <stdio.h>
#include <stdint.h>
#include <string.h>

// key{d9dd 1cb9 dc13 ebc3dc37 80d76123 ee34}
//
//
extern uint32_t to_byte(uint8_t b); 
extern uint32_t read_bytes(uint32_t base, const char *p, int l);

int keycomp(const char *key)
{
    int ret;
    int k2, k3;
    int ll = strlen(key);
    uint8_t k5a;
    uint8_t k5b;
    uint8_t k67;
    uint16_t k89_10_11;
    uint32_t k12_19;
    uint32_t temp;
    uint32_t ok;
    uint32_t AAAA;
    uint32_t k20_27;
    uint32_t k28_31;

    // length check: 32 chars + key{}
    if(ll != 37) {
        return ll;
    }

    key += 4;

    // digit 0 easy
    // d
    if(key[0] != 'd') {
        return -2;
    }

    // digit 1
    // 9
    if(to_byte(key[1]) != 9) {
        return -3;
    }

    //digit 2
    // d
    k2 = to_byte(key[2]);
    if(k2 * 2 != 0xd*2) {
        return -4;
    }

    //digit 3
    // d
    k3 = to_byte(key[3]);
    if( ((k3 + 1) / 2) != 7) {
        
        return -5;
    }

    // digit 4
    // 1
    if((key[4] & 0xF) == 0x1  && (key[4] & 0xF0) == 0x30) {
        ret = -4;
    } else {
        return -6;
    }

    // digit 5
    // c
    k5a = (key[5] & 0x0F);
    k5b = (key[5] & 0xF0);
    if(k5a == 0x3 && k5b == 0x60){
        ret += 4;
    } else {
        ret += 5;
    }


    //digit 6
    //digit 7
    // b9
    k67 = to_byte(key[6]);
    k67 << 4;
    k67 |= (to_byte(key[7]));
    if((~k67) == 0x46) {
        ret -= 1;
    }else {
        ret <<= ret; 
    }

    if(ret != 0)
    {
        return -7;
    }

    k89_10_11 = read_bytes(0, &key[8], 4);

    if((k89_10_11 | 0x5555) == 0xDD57 && (k89_10_11 | 0xAAAA) == 0xFEBB)
    // correct ret = 0xAAAA
    {
        ret = 0xAAAA;
    } else {
        ret = 0xBBBB;
    }

    k12_19 = read_bytes(0, &key[12], 8);
    // ^= 4b4fAAAA

    temp = k12_19 ^ 0xA488769D;
    ok = temp >> 16;
    AAAA = temp & 0x0000FFFF;
    if(ok == 'OK' && AAAA == ret) {
        ret = 0;
    } else {
        ret = 0xbcdf;
    }

    k20_27 = read_bytes(ret, &key[20], 8);
    // 80d76123
    k20_27 -= 0x3;
    if((k20_27 & 7) != 0) {return -21;}
    k20_27 -= 0x80000000;
    if(k20_27>0xFFFFFFF) {return -22;}
    k20_27 ^= 0xD00000;
    k20_27 >>= 4;
    k20_27 -= 226;
    k20_27 /= 10000;
    if(k20_27 != 3){
        return k20_27;
    }
    
   k28_31 = read_bytes(ret, &key[28], 4); 
   if(key[28] == 'd' && key[29] == 'd')
   {
       ret ^= k28_31;
   } else if (key[28] == key[29]) 
   {
        ret += 0xE + 1 - (key[31] - key[30]);
        ret -= to_byte(key[28]);
        if(ret == 0 && to_byte(key[31]) != 4) {
            ret = -32;
        }
   } else {
       ret = k28_31;
   }

    return ret;
} 
