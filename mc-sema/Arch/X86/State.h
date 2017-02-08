
#pragma once

#include <stdint.h>

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

#if defined(_WIN64) && !defined(__x86_64__)
#define __x86_64__
#endif


#ifdef _WIN32
typedef struct alignas(16) __uint128_t {
    char pad[16];
} PACKED uint128_t;
#else
typedef unsigned uint128_t __attribute__((mode(TI), aligned(16)));
#endif

#ifdef _WIN32
typedef union { double d; char pad[16];} PACKED LDOUBLE;
#pragma pack(push, 1)
#else
typedef long double LDOUBLE;
#endif

#ifdef __x86_64__
typedef uint64_t reg_t;
#else
typedef uint32_t reg_t;
#endif

//structure for register state
struct alignas(16) RegState {

  reg_t RIP;
  reg_t RAX;
  reg_t RBX;
  reg_t RCX;
  reg_t RDX;
  reg_t RSI;
  reg_t RDI;
  reg_t RSP;
  reg_t RBP;

  reg_t R8;
  reg_t R9;
  reg_t R10;
  reg_t R11;
  reg_t R12;
  reg_t R13;
  reg_t R14;
  reg_t R15;

  uint8_t CF;
  uint8_t PF;
  uint8_t AF;
  uint8_t ZF;
  uint8_t SF;
  uint8_t OF;
  uint8_t DF;

  LDOUBLE ST0;
  LDOUBLE ST1;
  LDOUBLE ST2;
  LDOUBLE ST3;
  LDOUBLE ST4;
  LDOUBLE ST5;
  LDOUBLE ST6;
  LDOUBLE ST7;

  uint8_t FPU_FLAG_BUSY;
  uint8_t FPU_FLAG_C3;
  // No FPU top.
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
  uint8_t FPU_FLAG_IE;

  uint8_t FPU_CONTROL_X;
  uint8_t FPU_CONTROL_RC;
  uint8_t FPU_CONTROL_PC;
  uint8_t FPU_CONTROL_PM;
  uint8_t FPU_CONTROL_UM;
  uint8_t FPU_CONTROL_OM;
  uint8_t FPU_CONTROL_ZM;
  uint8_t FPU_CONTROL_DM;
  uint8_t FPU_CONTROL_IM;

  uint8_t _padding[10];

  // XMM registers.
  uint128_t XMM0;
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
  uint128_t XMM15;
};

