
#pragma once

#include <stdint.h>
#include <stdalign.h>

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

#ifdef __cplusplus
//structure for register state
struct alignas(16) RegState {
#else
typedef struct _RegState {
#endif

  reg_t PC;
  reg_t ZERO;
  reg_t AT;
  reg_t V0;
  reg_t V1;
  reg_t A0;
  reg_t A1;
  reg_t A2;
  reg_t A3;
  reg_t T0;

  reg_t T1;
  reg_t T2;
  reg_t T3;
  reg_t T4;
  reg_t T5;
  reg_t T6;
  reg_t T7;
  reg_t S0;

  reg_t S1;
  reg_t S2;
  reg_t S3;
  reg_t S4;
  reg_t S5;
  reg_t S6;
  reg_t S7;
  reg_t T8;
  reg_t T9;

  reg_t K0;
  reg_t K1;
  reg_t GP;
  reg_t SP;
  reg_t FP;
  reg_t RA;
}
#ifndef __cplusplus
RegState
#endif
;

