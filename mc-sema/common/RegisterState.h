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

// nativefpu = long double
// = 96 bits of storage and
// 80 bits of data
//typedef long double nativefpu;
#ifdef _WIN32
#pragma pack(push, 1)
#endif
typedef struct _nativefpu {
  uint8_t b[12];
//only on 64-bit platforms, the JIT emits this struct as 16-byte aligned
#ifdef __x86_64__
  uint8_t pad[4];
#endif
#ifdef __cplusplus
    _nativefpu& operator=(const _nativefpu& rhs) {
        if(this == &rhs)
            return *this;

        memcpy(&(this->b[0]), &(rhs.b[0]), sizeof(this->b));
        return *this;
    }
	bool operator==(const _nativefpu &other ) const {
		return (this->b[0] == other.b[0] &&
				this->b[1] == other.b[1] &&
				this->b[2] == other.b[2] &&
				this->b[3] == other.b[3] &&
				this->b[4] == other.b[4] &&
				this->b[5] == other.b[5] &&
				this->b[6] == other.b[6] &&
				this->b[7] == other.b[7] &&
				this->b[8] == other.b[8] &&
				this->b[9] == other.b[9] &&
				this->b[10] == other.b[10] &&
				this->b[11] == other.b[11]);
    }

  std::string printMe(void) const {
    std::ostringstream  oss;

    int32_t  k = this->b[0];
    oss << "0x" << std::hex << k;
    k = this->b[1];
    oss << " 0x" << std::hex << k;
    k = this->b[2];
    oss << " 0x" << std::hex << k;
    k = this->b[3];
    oss << " 0x" << std::hex << k;
    k = this->b[4];
    oss << " 0x" << std::hex << k;
    k = this->b[5];
    oss << " 0x" << std::hex << k;
    k = this->b[6];
    oss << " 0x" << std::hex << k;
    k = this->b[7];
    oss << " 0x" << std::hex << k;
    k = this->b[8];
    oss << " 0x" << std::hex << k;
    k = this->b[9];
    oss << " 0x" << std::hex << k;
    k = this->b[10];
    oss << " 0x" << std::hex << k;
    k = this->b[11];
    oss << " 0x" << std::hex << k;

    return oss.str();
  }
#endif

} PACKED nativefpu;
#ifdef _WIN32
#pragma pack(pop)
#endif

#ifdef _WIN32
#pragma pack(push, 1)
#endif
typedef struct _segmentoffset{
    uint16_t seg;
#ifdef __x86_64__
    uint64_t off;
#else
    uint32_t off;
#endif
} PACKED segmentoffset; // 6 bytes
#ifdef _WIN32
#pragma pack(pop)
#endif


// This is supposed to be eight 2-bit integers, but LLVM represents
// these as 1 byte per 2-bit integer. Since we memcpy, mimic the
// llvm format.

#define STREGS_MAX 8

#ifdef _WIN32
#pragma pack(push, 1)
#endif
typedef struct _fputag {
    uint8_t tag[STREGS_MAX];
#ifdef __cplusplus
	bool operator==(const _fputag &other ) const {
		return (this->tag[0] == other.tag[0] &&
				this->tag[1] == other.tag[1] &&
				this->tag[2] == other.tag[2] &&
				this->tag[3] == other.tag[3] &&
				this->tag[4] == other.tag[4] &&
				this->tag[5] == other.tag[5] &&
				this->tag[6] == other.tag[6] &&
				this->tag[7] == other.tag[7]);
    }

  std::string printMe(void) const {
    std::ostringstream  oss;

    int32_t  k = this->tag[0];
    oss << "0x" << std::hex << k;
    k = this->tag[1];
    oss << " 0x" << std::hex << k;
    k = this->tag[2];
    oss << " 0x" << std::hex << k;
    k = this->tag[3];
    oss << " 0x" << std::hex << k;
    k = this->tag[4];
    oss << " 0x" << std::hex << k;
    k = this->tag[5];
    oss << " 0x" << std::hex << k;
    k = this->tag[6];
    oss << " 0x" << std::hex << k;
    k = this->tag[7];
    oss << " 0x" << std::hex << k;

    return oss.str();

  }
#endif

} PACKED fputag;
#ifdef _WIN32
#pragma pack(pop)
#endif

#ifdef _WIN32
#pragma pack(push, 1)
#endif
typedef struct _xmmregstate {
    uint8_t tag[16];
#ifdef __cplusplus
	bool operator==(const _xmmregstate &other ) const {
		return (this->tag[0] == other.tag[0] &&
				this->tag[1] == other.tag[1] &&
				this->tag[2] == other.tag[2] &&
				this->tag[3] == other.tag[3] &&
				this->tag[4] == other.tag[4] &&
				this->tag[5] == other.tag[5] &&
				this->tag[6] == other.tag[6] &&
				this->tag[7] == other.tag[7] &&
				this->tag[8] == other.tag[8] &&
				this->tag[9] == other.tag[9] &&
				this->tag[10] == other.tag[10] &&
				this->tag[11] == other.tag[11] &&
				this->tag[12] == other.tag[12] &&
				this->tag[13] == other.tag[13] &&
				this->tag[14] == other.tag[14] &&
				this->tag[15] == other.tag[15]);
    }

    std::string printMe(void) const {
        std::stringstream oss;
        for(unsigned  i = 0; i < 16; i++) {
            oss << " 0x" << std::hex << (int32_t) this->tag[i];
        }
        return oss.str();
    }
#endif
} PACKED xmmregstate;
#ifdef _WIN32
#pragma pack(pop)
#endif


#ifdef _WIN32
#pragma pack(push, 1)
#endif
typedef struct _fpuregs {
    nativefpu st[STREGS_MAX];

#ifdef __cplusplus
	bool operator==(const _fpuregs &other ) const {
		return (this->st[0] == other.st[0] &&
				this->st[1] == other.st[1] &&
				this->st[2] == other.st[2] &&
				this->st[3] == other.st[3] &&
				this->st[4] == other.st[4] &&
				this->st[5] == other.st[5] &&
				this->st[6] == other.st[6] &&
				this->st[7] == other.st[7]);
    }
#endif
} PACKED fpuregs; // 96 bytes
#ifdef _WIN32
#pragma pack(pop)
#endif

#ifdef _WIN32
#pragma pack(push, 1)
#endif
typedef struct _fpuflags {
    uint8_t BUSY;
    uint8_t C3;
    uint8_t TOP;
    uint8_t C2;
    uint8_t C1;
    uint8_t C0;
    uint8_t ES;
    uint8_t SF;
    uint8_t PE;
    uint8_t UE;
    uint8_t OE;
    uint8_t ZE;
    uint8_t DE;
    uint8_t IE;

#ifdef __cplusplus
	bool operator==(const _fpuflags &other ) const {
		return (this->BUSY == other.BUSY &&
				this->C3 == other.C3 &&
				this->TOP == other.TOP &&
				this->C2 == other.C2 &&
				this->C1 == other.C1 &&
				this->C0 == other.C0 &&
				this->ES == other.ES &&
				this->SF == other.SF &&
				this->PE == other.PE &&
				this->UE == other.UE &&
				this->OE == other.OE &&
				this->ZE == other.ZE &&
				this->DE == other.DE &&
				this->IE == other.IE);
    }
#endif
} PACKED fpuflags; // 14 bytes
#ifdef _WIN32
#pragma pack(pop)
#endif

#ifdef _WIN32
#pragma pack(push, 1)
#endif
typedef struct _fpucontrol {
    uint8_t X;
    uint8_t RC;
    uint8_t PC;
    uint8_t PM;
    uint8_t UM;
    uint8_t OM;
    uint8_t ZM;
    uint8_t DM;
    uint8_t IM;

#ifdef __cplusplus
	bool operator==(const _fpucontrol &other) const {
		return (this->X == other.X &&
                this->RC == other.RC &&
                this->PC == other.PC &&
                this->PM == other.PM &&
                this->UM == other.UM &&
                this->OM == other.OM &&
                this->ZM == other.ZM &&
                this->DM == other.DM &&
                this->IM == other.IM);
    }
#endif
} PACKED fpucontrol; // 9 bytes
#ifdef _WIN32
#pragma pack(pop)
#endif

#ifdef _WIN32
#pragma pack(push, 1)
#endif
//structure for register state
typedef struct _RegState {
    //the big registers
#ifndef __x86_64__ 
	uint32_t	EAX;
	uint32_t	EBX;
	uint32_t	ECX;
	uint32_t 	EDX;
	uint32_t	ESI;
	uint32_t	EDI;
	uint32_t	ESP;
	uint32_t	EBP;
#else
	uint64_t 	RAX;
	uint64_t 	RBX;
	uint64_t 	RCX;
	uint64_t 	RDX;
	uint64_t	RSI;
	uint64_t 	RDI;
	uint64_t 	RSP;
	uint64_t 	RBP;
	uint64_t 	R8;
	uint64_t	R9;
	uint64_t	R10;
	uint64_t	R11;
	uint64_t	R12;
	uint64_t	R13;
	uint64_t	R14;
	uint64_t	R15;
	uint64_t    RIP;
#endif

    //the flags
    uint8_t	CF;
    uint8_t	PF;
    uint8_t	AF;
    uint8_t	ZF;
    uint8_t	SF;
    uint8_t	OF;
    uint8_t	DF; // 7 bytes
    fpuregs     ST_regs; //  96 bytes
    fpuflags    FPU_FLAGS; // 14 bytes
    fpucontrol  FPU_CONTROL; // 9 bytes
    fputag      FPU_TAG; // 8 bytes
    segmentoffset FPU_LASTIP; // 8 bytes
    segmentoffset FPU_LASTDATA; // 8 bytes
    uint16_t    FPU_FOPCODE; // 2 bytes

    //xmm registers
    xmmregstate      XMM0;
    xmmregstate      XMM1;
    xmmregstate      XMM2;
    xmmregstate      XMM3;
    xmmregstate      XMM4;
    xmmregstate      XMM5;
    xmmregstate      XMM6;
    xmmregstate      XMM7;
#ifdef __x86_64__
    xmmregstate      XMM8;
    xmmregstate      XMM9;
    xmmregstate      XMM10;
    xmmregstate      XMM11;
    xmmregstate      XMM12;
    xmmregstate      XMM13;
    xmmregstate      XMM14;
    xmmregstate      XMM15;
#endif


    // not registers, but necessary to support calls
    // via register/memory
#ifdef __x86_64__
    uint64_t stack_base; // biggest number ESP can be
    uint64_t stack_limit; // smallest number ESP can be
#else
    uint32_t stack_base; // biggest number ESP can be
    uint32_t stack_limit; // smallest number ESP can be
#endif
#ifdef __cplusplus
    void printMe(const std::string &name) const {
#ifdef DEBUG
        const char *cstr = name.c_str();
        printf("\n");
        printf("%s: EAX=0x%16x\n", cstr, this->RAX);
        printf("%s: EBX=0x%16x\n", cstr, this->RBX);
        printf("%s: ECX=0x%16x\n", cstr, this->RCX);
        printf("%s: EDX=0x%16x\n", cstr, this->RDX);
        printf("%s: ESI=0x%16x\n", cstr, this->RSI);
        printf("%s: EDI=0x%16x\n", cstr, this->RDI);
        printf("%s: ESP=0x%16x\n", cstr, this->RSP);
        printf("%s: EBP=0x%16x\n", cstr, this->RBP);
        printf("%s: CF: %d PF: %d AF: %d ZF: %d SF: %d OF: %d DF: %d\n",
                cstr, this->CF, this->PF, this->AF, this->ZF, this->SF, this->OF, this->DF);

        for(int i = 0; i < STREGS_MAX; i++)
        {
            printf("%s: ST%d: %s\n", cstr, i, this->ST_regs.st[i].printMe().c_str());
        }
        printf("%s: B: %d C3: %d TOP: %d C2: %d C1: %d C0: %d ES: %d SF: %d\n"
               "%s: PE: %d UE: %d OE: %d ZE: %d DE %d IE: %d\n",
               cstr, this->FPU_FLAGS.BUSY, this->FPU_FLAGS.C3, this->FPU_FLAGS.TOP,
               this->FPU_FLAGS.C2, this->FPU_FLAGS.C1, this->FPU_FLAGS.C0,
               this->FPU_FLAGS.ES, this->FPU_FLAGS.SF, cstr, this->FPU_FLAGS.PE,
               this->FPU_FLAGS.UE, this->FPU_FLAGS.OE, this->FPU_FLAGS.ZE,
               this->FPU_FLAGS.DE, this->FPU_FLAGS.IE);
        printf("%s: X: %d RC: %d PC: %d PM: %d UM: %d OM: %d ZM: %d DM: %d IM: %d\n",
                cstr, this->FPU_CONTROL.X, this->FPU_CONTROL.RC,
                this->FPU_CONTROL.PC, this->FPU_CONTROL.PM, this->FPU_CONTROL.UM,
                this->FPU_CONTROL.OM, this->FPU_CONTROL.ZM, this->FPU_CONTROL.DM,
                this->FPU_CONTROL.IM);
        printf("%s: FPUTAG=%s\n", cstr, this->FPU_TAG.printMe().c_str());
        printf("\n");
        fflush(stdout);
#endif
    }
#endif

#ifdef __cplusplus
	bool operator==(const _RegState &other ) const {
#ifdef __x86_64__
		return (this->RAX == other.RAX &&
				this->RBX == other.RBX &&
				this->RCX == other.RCX &&
				this->RDX == other.RDX &&
				this->RDI == other.RDI &&
				this->RBP == other.RBP &&
				this->RSP == other.RSP &&
				this->R8 == other.R8 &&
				this->R9 == other.R9 &&
				this->R10 == other.R10 &&
				this->R11 == other.R11 &&
				this->R12 == other.R12 &&
				this->R13 == other.R13 &&
				this->R14 == other.R14 &&
				this->R15 == other.R15 &&
				this->CF == other.CF &&
				this->PF == other.PF &&
				this->AF == other.AF &&
				this->SF == other.SF &&
				this->OF == other.OF &&
				this->DF == other.DF &&
				this->ST_regs == other.ST_regs &&
                this->FPU_FLAGS == other.FPU_FLAGS &&
                this->FPU_CONTROL == other.FPU_CONTROL &&
                this->FPU_FOPCODE == other.FPU_FOPCODE &&
                this->FPU_TAG == other.FPU_TAG);
#else
		return (this->EAX == other.EAX &&
				this->EBX == other.EBX &&
				this->ECX == other.ECX &&
				this->EDX == other.EDX &&
				this->EDI == other.EDI &&
				this->EBP == other.EBP &&
				this->ESP == other.ESP &&
				this->CF == other.CF &&
				this->PF == other.PF &&
				this->AF == other.AF &&
				this->SF == other.SF &&
				this->OF == other.OF &&
				this->DF == other.DF &&
				this->ST_regs == other.ST_regs &&
                this->FPU_FLAGS == other.FPU_FLAGS &&
                this->FPU_CONTROL == other.FPU_CONTROL &&
                this->FPU_FOPCODE == other.FPU_FOPCODE &&
                this->FPU_TAG == other.FPU_TAG);
#endif
	}
#endif

} PACKED RegState;
#ifdef _WIN32
#pragma pack(pop)
#endif


#ifndef ONLY_STRUCT
// get the value of st(reg_index)
nativefpu FPU_GET_REG(RegState *state, unsigned reg_index)
{
    unsigned rnum = state->FPU_FLAGS.TOP + reg_index;

    assert(reg_index < STREGS_MAX);
    rnum %= STREGS_MAX;

    return state->ST_regs.st[rnum];
}

// set the value of st(reg_index)
void FPU_SET_REG(RegState *state, unsigned reg_index, nativefpu val)
{

    unsigned rnum = state->FPU_FLAGS.TOP + reg_index;

    assert(reg_index < STREGS_MAX);
    rnum %= STREGS_MAX;

    state->ST_regs.st[rnum] = val;
}

long double NATIVEFPU_TO_LD(const nativefpu *nf)
{
#ifdef _WIN32
	// sanity check
	long double ld = 0;
#ifndef _WIN64
	_asm {
		MOV eax, dword ptr nf
		_emit 0xDB
		_emit 0x28
		;FLD tbyte ptr [eax]	; load 80bits into fpu
		LEA eax, dword ptr ld		; get address of ld
		FSTP qword ptr [eax]	; store 64-bits into ld
	}
#else
	assert(sizeof(nf) == sizeof(ld));
	memcpy(&ld, nf, sizeof(ld));
#endif
	return ld;
#else
	long double ld;
	assert(sizeof(*nf) == sizeof(ld));
	memcpy(&ld, nf, sizeof(ld));
	return ld;
#endif
}

void LD_TO_NATIVEFPU(long double ld, nativefpu *nf)
{
#ifdef _WIN32
#ifndef _WIN64
	_asm {
		LEA  eax, dword ptr ld		; get address of ld
		FLD  qword ptr [eax]	; load 64bits into fpu
		MOV eax, dword ptr nf
		_emit 0xDB
		_emit 0x38
		;FSTP tbyte ptr [eax]	; store 80-bits into nf
	}
#else
#endif
#else
	assert(sizeof(ld) == sizeof(*nf));
	memcpy(nf, &ld, sizeof(*nf));
#endif
}

#endif

#ifdef __cplusplus
} // namespace mcsema
#endif
