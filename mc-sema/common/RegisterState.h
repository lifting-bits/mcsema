#pragma once
#include <stdint.h>
#include <string.h>
#include <assert.h>

#ifdef __GNUC__
#define STDCALL __attribute__((__stdcall__))
#define PACKED  __attribute__((packed))
#elif defined(_WIN32)
#define STDCALL __stdcall
#define PACKED
#else
#define STDCALL
#define PACKED
#endif

#ifdef _WIN64
#define __x86_64__
#endif

//#define DEBUG

#ifdef __cplusplus
namespace mcsema {
#endif
// struct to handle native
// x87 FPU 80-bit types.
// aka X86_Fp80Ty
// THIS DOES NOT WORK
// turns out 80-bit native FPU entries
// aka long double take up 96 bits of
// storage but only use 80 bits of data
// who knew?
// see email thread:
// http://lists.cs.uiuc.edu/pipermail/llvm-commits/Week-of-Mon-20070924/054064.html
/*typedef struct _nativefpu {
 uint8_t b0;
 uint8_t b1;
 uint8_t b2;
 uint8_t b3;
 uint8_t b4;
 uint8_t b5;
 uint8_t b6;
 uint8_t b7;
 uint8_t b8;
 uint8_t b9;
 } __attribute ((packed)) nativefpu; // 80 bit  aka 10 bytes
 */

// This is supposed to be eight 2-bit integers, but LLVM represents
// these as 1 byte per 2-bit integer. Since we memcpy, mimic the
// llvm format.

#define STREGS_MAX 8

#ifdef _WIN32
#pragma pack(push, 1)
#endif
typedef struct _fputag {
  uint8_t tag[STREGS_MAX];
}PACKED fputag;
#ifdef _WIN32
#pragma pack(pop)
#endif

typedef unsigned uint128_t __attribute__((mode(TI)));

#ifdef _WIN32
#pragma pack(push, 1)
#endif
typedef struct _fpuregs {
  long double st[STREGS_MAX];
} PACKED fpuregs;  // 96 bytes
#ifdef _WIN32
#pragma pack(pop)
#endif

#ifdef __x86_64__
typedef uint64_t reg_t;
#define REG(suffix) R ## suffix
#else
typedef uint32_t reg_t;
#define REG(suffix) E ## suffix
#endif

#ifdef _WIN32
#pragma pack(push, 1)
#endif
//structure for register state
typedef struct _RegState {

  reg_t REG(IP);  // Offset 0.
  reg_t REG(AX);
  reg_t REG(BX);
  reg_t REG(CX);
  reg_t REG(DX);
  reg_t REG(SI);
  reg_t REG(DI);
  reg_t REG(SP);
  reg_t REG(BP);  // Offset 8.

  // R8 - R15 stored at end so that we can use some of the same maps in
  // RegisterUsage.cpp.

  //the flags
  uint8_t CF;  // Offset 9.
  uint8_t PF;
  uint8_t AF;
  uint8_t ZF;
  uint8_t SF;
  uint8_t OF;
  uint8_t DF;  // Offset 15.

  fpuregs ST_regs;  // Offset 16; 96 bytes.

  uint8_t FPU_FLAG_BUSY;  // Offset 17.
  uint8_t FPU_FLAG_C3;
  uint8_t FPU_FLAG_TOP;
  uint8_t FPU_FLAG_C2;
  uint8_t FPU_FLAG_C1;
  uint8_t FPU_FLAG_C0;
  uint8_t FPU_FLAG_ES;
  uint8_t FPU_FLAG_SF;
  uint8_t FPU_FLAG_PE;
  uint8_t FPU_FLAG_UE;
  uint8_t FPU_FLAG_OE;
  uint8_t FPU_FLAG_ZE;
  uint8_t FPU_FLAG_DE;
  uint8_t FPU_FLAG_IE;  // Offset 30.

  uint8_t FPU_CONTROL_X;  // Offset 31.
  uint8_t FPU_CONTROL_RC;
  uint8_t FPU_CONTROL_PC;
  uint8_t FPU_CONTROL_PM;
  uint8_t FPU_CONTROL_UM;
  uint8_t FPU_CONTROL_OM;
  uint8_t FPU_CONTROL_ZM;
  uint8_t FPU_CONTROL_DM;
  uint8_t FPU_CONTROL_IM;  // Offset 39.

  fputag FPU_TAG;  // Offset 40; 8 bytes.

  uint16_t FPU_LASTIP_SEG;  // Offset 41.
  reg_t FPU_LASTIP_OFF;

  uint16_t FPU_LASTDATA_SEG;  // Offset 43;
  reg_t FPU_LASTDATA_OFF;

  uint16_t FPU_FOPCODE;  // Offset 45; 2 bytes/

  // XMM registers.
  uint128_t XMM0;  // Offset 46.
  uint128_t XMM1;
  uint128_t XMM2;
  uint128_t XMM3;
  uint128_t XMM4;
  uint128_t XMM5;
  uint128_t XMM6;
  uint128_t XMM7;
  uint128_t XMM8;
  uint128_t XMM9;
  uint128_t XMM10;
  uint128_t XMM11;
  uint128_t XMM12;
  uint128_t XMM13;
  uint128_t XMM14;
  uint128_t XMM15;  // Offset 61.

  // not registers, but necessary to support calls
  // via register/memory
  reg_t stack_base;  // Offset 62; biggest number ESP can be
  reg_t stack_limit;  // Offset 63; smallest number ESP can be

#ifdef __x86_64__
  reg_t  R8;  // Offset 64.
  reg_t  R9;
  reg_t  R10;
  reg_t  R11;
  reg_t  R12;
  reg_t  R13;
  reg_t  R14;
  reg_t  R15;  // Offset 71.
#endif
}PACKED RegState;
#ifdef _WIN32
#pragma pack(pop)
#endif

#ifndef ONLY_STRUCT
// get the value of st(reg_index)
nativefpu FPU_GET_REG(RegState *state, unsigned reg_index) {
  unsigned rnum = state->FPU_FLAGS.TOP + reg_index;

  assert(reg_index < STREGS_MAX);
  rnum %= STREGS_MAX;

  return state->ST_regs.st[rnum];
}

// set the value of st(reg_index)
void FPU_SET_REG(RegState *state, unsigned reg_index, nativefpu val) {

  unsigned rnum = state->FPU_FLAGS.TOP + reg_index;

  assert(reg_index < STREGS_MAX);
  rnum %= STREGS_MAX;

  state->ST_regs.st[rnum] = val;
}

long double NATIVEFPU_TO_LD(const nativefpu *nf) {
#ifdef _WIN32
  // sanity check
  long double ld = 0;
#ifndef _WIN64
  _asm {
    MOV eax, dword ptr nf
    _emit 0xDB
    _emit 0x28
    ;FLD tbyte ptr [eax]; load 80bits into fpu
    LEA eax, dword ptr ld; get address of ld
    FSTP qword ptr [eax]; store 64-bits into ld
  }
#else
  assert(sizeof(nf) == sizeof(ld));
  memcpy(&ld, nf, sizeof(ld));
#endif
  return ld;
#else
  long double ld;
  assert(sizeof( *nf) == sizeof(ld));
  memcpy( &ld, nf, sizeof(ld));
  return ld;
#endif
}

void LD_TO_NATIVEFPU(long double ld, nativefpu *nf) {
#ifdef _WIN32
#ifndef _WIN64
  _asm {
    LEA eax, dword ptr ld; get address of ld
    FLD qword ptr [eax]; load 64bits into fpu
    MOV eax, dword ptr nf
    _emit 0xDB
    _emit 0x38
    ;FSTP tbyte ptr [eax]; store 80-bits into nf
  }
#else
#endif
#else
  assert(sizeof(ld) == sizeof( *nf));
  memcpy(nf, &ld, sizeof( *nf));
#endif
}

#endif

#ifdef __cplusplus
}  // namespace mcsema
#endif
