/*
Copyright (c) 2013, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of the {organization} nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include "toLLVM.h"
#include "raiseX86.h"
#include "X86.h"

#include "RegisterUsage.h"

#include "JumpTables.h"

#include "x86Helpers.h"
#include "x86Instrs_fpu.h"
#include "x86Instrs_MOV.h"
#include "InstructionDispatch.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Support/Debug.h"
#include "x86Instrs_flagops.h"
#include "../common/to_string.h"

using namespace std;
using namespace llvm;


Value* getGlobalRegAsPtr(BasicBlock *B, MCSemaRegs reg)
{
    Function *F = B->getParent();
    Module *M = F->getParent();
    unsigned int regWidth = getPointerSize(M);

    Value *arg = F->arg_begin();

    int globalRegsOff = getSystemArch(M) == _X86_?
    		x86::getRegisterOffset(reg) : x86_64::getRegisterOffset(reg);

    Value *globalGlobalGEPV[] = {
        CONST_V(B, regWidth, 0),
        CONST_V<32>(B, globalRegsOff),
        CONST_V(B, regWidth, 0) };

    // Get element pointer.
    Instruction *gGlobalPtr = aliasMCSemaScope(GetElementPtrInst::CreateInBounds(arg, globalGlobalGEPV, "", B));
    // Cast pointer to int8* for use with memcpy.
    Instruction *globalCastPtr = aliasMCSemaScope(CastInst::CreatePointerCast(
        gGlobalPtr, Type::getInt8PtrTy(B->getContext()), "", B));

    return globalCastPtr;
}

Value* getGlobalFPURegsAsPtr(BasicBlock *B)
{
    return getGlobalRegAsPtr(B, ST0);
}

Value* getLocalRegAsPtr(BasicBlock *B, MCSemaRegs reg)
{
    Function *F = B->getParent();
    Module *M = F->getParent();

    unsigned int regWidth = getPointerSize(M);

    Value *localReg = getSystemArch(M) == _X86_?
    		x86::lookupLocal(F, reg) : x86_64::lookupLocal(F, reg);

    // Need to get pointer to array[0] via GEP.
    Value *localGEP[] = {
        CONST_V(B, regWidth, 0),
        CONST_V<32>(B, 0)};
    Instruction *localPtr = noAliasMCSemaScope(GetElementPtrInst::CreateInBounds(
        localReg, localGEP, "", B));

    // Cast pointer to an Int8* for use with memcpy.
    Instruction *localCastPtr = noAliasMCSemaScope(CastInst::CreatePointerCast(
            localPtr, Type::getInt8PtrTy(B->getContext()), "", B));

    return localCastPtr;
}

Value* getLocalFPURegsAsPtr(BasicBlock *B)
{
    return getLocalRegAsPtr(B, ST0);
}

void writeLocalsToContext(BasicBlock *B, unsigned bits, StoreSpillType whichRegs)
{
    Function *F = B->getParent();
    // Look up the argument value to this function.
    TASSERT(F->arg_size() >= 1, "need at least one argument to write locals to context");
    Value       *arg = F->arg_begin();

    // There are a few occasions where we have to take the entirety of a
    // context structure and 'spill' them to locally allocated values.
    switch(bits) {
        case 32:
        {
            // UPDATEREGS - when we add something to the 'regs' struct change
            // here to reflect that.
            // Do a GEP on the 'regs' structure for the appropriate field offset.
#define STORE(nm, nm_in) {\
            std::string regnm = x86::getRegisterName(nm);\
            Value   *localVal = x86::lookupLocal(F, nm);\
            if (localVal == NULL)\
              throw TErr(__LINE__, __FILE__, "Could not find val"+regnm);\
            int eaxOff = x86::getRegisterOffset(nm);\
            Value *eaxGEPV[] =\
                { ConstantInt::get(Type::getInt32Ty(B->getContext()), 0),\
                ConstantInt::get(Type::getInt32Ty(B->getContext()), eaxOff)};\
            Instruction *GEP = GetElementPtrInst::CreateInBounds(arg,\
                eaxGEPV, regnm, B);\
            Value *loadedVal = x86::R_READ<32>(B, nm_in);\
            Instruction *st = aliasMCSemaScope(new StoreInst(loadedVal, GEP, B)); \
            TASSERT(st != NULL, "");\
            }

            STORE(EAX, X86::EAX);
            STORE(EBX, X86::EBX);
            STORE(ECX, X86::ECX);
            STORE(EDX, X86::EDX);
            STORE(ESI, X86::ESI);
            STORE(EDI, X86::EDI);
            STORE(ESP, X86::ESP);
            STORE(EBP, X86::EBP);
#define STORE_SAMEWIDTH(nm) { \
            std::string regnm = x86::getRegisterName(nm);\
            Value   *localVal = x86::lookupLocal(F, nm); \
            if( localVal == NULL ) \
              throw TErr(__LINE__, __FILE__, "Could not find val: "+regnm); \
            int off = x86::getRegisterOffset(nm); \
            Value   *GEPV[] =  \
                { ConstantInt::get(Type::getInt32Ty(B->getContext()), 0), \
                ConstantInt::get(Type::getInt32Ty(B->getContext()), off)}; \
            Instruction *GEP = GetElementPtrInst::CreateInBounds(arg, \
                GEPV, regnm, B); \
            Value   *loadedVal = GENERIC_READREG(B, nm); \
            StoreInst *si = new StoreInst(loadedVal, GEP, B);\
            si->setAlignment(1); \
            Instruction *st = aliasMCSemaScope(si); \
            TASSERT(st != NULL, "" ); \
        }
#define STORE_F(nm) STORE_SAMEWIDTH(nm)

            STORE_F(CF);
            STORE_F(PF);
            STORE_F(AF);
            STORE_F(ZF);
            STORE_F(SF);
            STORE_F(OF);
            STORE_F(DF);

            //use llvm.memcpy to copy locals to context
            // SOURCE: get pointer to FPU locals
            Value *localFPU = getLocalFPURegsAsPtr(B);
            // DEST: get pointer to FPU globals
            Value *globalFPU = getGlobalFPURegsAsPtr(B);
            // SIZE: 8 FPU regs * sizeof(x86_FP80Ty)
            // ALIGN = 4
            // Volatile = FALSE
            DataLayout  td(static_cast<Module*>(F->getParent()));
            uint32_t fpu_arr_size =
                (uint32_t)td.getTypeAllocSize(
                        Type::getX86_FP80Ty(B->getContext())) * NUM_FPU_REGS;
            Instruction *mcp_fpu = aliasMCSemaScope(callMemcpy(B, globalFPU, localFPU, fpu_arr_size, 4, false));

            STORE_F(FPU_B);
            STORE_F(FPU_C3);
            // TOP is a 3-bit integer and not
            // a one bit flag, but STORE_F
            // just zero-extends and writes to
            // a 32-bit integer.
            STORE_F(FPU_TOP);
            STORE_F(FPU_C2);
            STORE_F(FPU_C1);
            STORE_F(FPU_C0);
            STORE_F(FPU_ES);
            STORE_F(FPU_SF);
            STORE_F(FPU_PE);
            STORE_F(FPU_UE);
            STORE_F(FPU_OE);
            STORE_F(FPU_ZE);
            STORE_F(FPU_DE);
            STORE_F(FPU_IE);

            // FPU CONTROL FLAGS
            STORE_F(FPU_X);
            STORE_F(FPU_RC);
            STORE_F(FPU_PC);
            STORE_F(FPU_PM);
            STORE_F(FPU_UM);
            STORE_F(FPU_OM);
            STORE_F(FPU_ZM);
            STORE_F(FPU_DM);
            STORE_F(FPU_IM);

            // SOURCE: get pointer to local tag word
            Value *localTag = getLocalRegAsPtr(B, FPU_TAG);
            // DEST: get pointer to FPU globals
            Value *globalTag = getGlobalRegAsPtr(B, FPU_TAG);
            // SIZE: 8 entries * sizeof(Int2Ty)
            // ALIGN = 4
            // Volatile = FALSE
            uint32_t tags_arr_size =
                (uint32_t)td.getTypeAllocSize(
                        Type::getIntNTy(B->getContext(), 2)) * NUM_FPU_REGS;

            Instruction *mcp = aliasMCSemaScope(callMemcpy(B, globalTag, localTag, tags_arr_size, 4, false));

            // last IP segment is a 16-bit value
            STORE_F(FPU_LASTIP_SEG);
            // 32-bit register not in X86 Namespace
            STORE_SAMEWIDTH(FPU_LASTIP_OFF);
            // last data segment is a 16-bit value
            STORE_F(FPU_LASTDATA_SEG);
            // 32-bit register not in X86 Namespace
            STORE_SAMEWIDTH(FPU_LASTDATA_OFF);

            STORE_F(FPU_FOPCODE);

            //vector instrs
            STORE_SAMEWIDTH(XMM0);
            STORE_SAMEWIDTH(XMM1);
            STORE_SAMEWIDTH(XMM2);
            STORE_SAMEWIDTH(XMM3);
            STORE_SAMEWIDTH(XMM4);
            STORE_SAMEWIDTH(XMM5);
            STORE_SAMEWIDTH(XMM6);
            STORE_SAMEWIDTH(XMM7);

            // stack base and limit
            STORE_SAMEWIDTH(STACK_BASE);
            STORE_SAMEWIDTH(STACK_LIMIT);
        }
        break;
#undef STORE
#undef STORE_F
#undef STORE_SAMEWIDTH
		case 64:
        {
#define STORE(nm, nm_in) {\
            std::string regnm = x86_64::getRegisterName(nm);\
            Value   *localVal = x86_64::lookupLocal(F, nm);\
            if (localVal == NULL)\
              throw TErr(__LINE__, __FILE__, "Could not find val"+regnm);\
            int eaxOff = x86_64::getRegisterOffset(nm);\
            Value *eaxGEPV[] =\
                { ConstantInt::get(Type::getInt64Ty(B->getContext()), 0),\
                ConstantInt::get(Type::getInt32Ty(B->getContext()), eaxOff)};\
            Instruction *GEP = GetElementPtrInst::CreateInBounds(arg,\
                eaxGEPV, regnm, B);\
            Value *loadedVal = x86_64::R_READ<64>(B, nm_in);\
            Instruction *st = aliasMCSemaScope(new StoreInst(loadedVal, GEP, B)); \
            TASSERT(st != NULL, "");\
            }
            STORE(RAX, X86::RAX);
            STORE(RBX, X86::RBX);
            STORE(RCX, X86::RCX);
            STORE(RDX, X86::RDX);
            STORE(RSI, X86::RSI);
            STORE(RDI, X86::RDI);
            STORE(RSP, X86::RSP);
            STORE(RBP, X86::RBP);

            STORE(R8, X86::R8);
            STORE(R9, X86::R9);
            STORE(R10, X86::R10);
            STORE(R11, X86::R11);
            STORE(R12, X86::R12);
            STORE(R13, X86::R13);
            STORE(R14, X86::R14);
            STORE(R15, X86::R15);
            STORE(RIP, X86::RIP);

#define STORE_SAMEWIDTH(nm) { \
            std::string regnm = x86_64::getRegisterName(nm);\
            Value   *localVal = x86_64::lookupLocal(F, nm); \
            if( localVal == NULL ) \
              throw TErr(__LINE__, __FILE__, "Could not find val: "+regnm); \
            int off = x86_64::getRegisterOffset(nm); \
            Value   *GEPV[] =  \
                { ConstantInt::get(Type::getInt64Ty(B->getContext()), 0), \
                ConstantInt::get(Type::getInt32Ty(B->getContext()), off)}; \
            Instruction *GEP = GetElementPtrInst::CreateInBounds(arg, \
                GEPV, regnm, B); \
            Value   *loadedVal = GENERIC_READREG(B, nm); \
            StoreInst *si = new StoreInst(loadedVal, GEP, B);\
            si->setAlignment(1); \
            Instruction *st = aliasMCSemaScope(si); \
            TASSERT(st != NULL, "" ); \
        }
#define STORE_F(nm) STORE_SAMEWIDTH(nm)

            STORE_F(CF);
            STORE_F(PF);
            STORE_F(AF);
            STORE_F(ZF);
            STORE_F(SF);
            STORE_F(OF);
            STORE_F(DF);

			// FPU registers are generally avoided on 64bit system
		    // SOURCE: get pointer to FPU locals
            Value *localFPU = getLocalFPURegsAsPtr(B);
            // DEST: get pointer to FPU globals
            Value *globalFPU = getGlobalFPURegsAsPtr(B);

			DataLayout  td(static_cast<Module*>(F->getParent()));
            uint32_t fpu_arr_size =
                (uint32_t)td.getTypeAllocSize(
                        Type::getX86_FP80Ty(B->getContext())) * NUM_FPU_REGS;

			Instruction *mcp_fpu = aliasMCSemaScope(callMemcpy(B, globalFPU, localFPU, fpu_arr_size, 8, false));

            STORE_F(FPU_B);
            STORE_F(FPU_C3);
            // TOP is a 3-bit integer and not
            // a one bit flag, but STORE_F
            // just zero-extends and writes to
            // a 32-bit integer.
            STORE_F(FPU_TOP);
            STORE_F(FPU_C2);
            STORE_F(FPU_C1);
            STORE_F(FPU_C0);
            STORE_F(FPU_ES);
            STORE_F(FPU_SF);
            STORE_F(FPU_PE);
            STORE_F(FPU_UE);
            STORE_F(FPU_OE);
            STORE_F(FPU_ZE);
            STORE_F(FPU_DE);
            STORE_F(FPU_IE);

            // FPU CONTROL FLAGS
            STORE_F(FPU_X);
            STORE_F(FPU_RC);
            STORE_F(FPU_PC);
            STORE_F(FPU_PM);
            STORE_F(FPU_UM);
            STORE_F(FPU_OM);
            STORE_F(FPU_ZM);
            STORE_F(FPU_DM);
            STORE_F(FPU_IM);

			            // SOURCE: get pointer to local tag word
            Value *localTag = getLocalRegAsPtr(B, FPU_TAG);
            // DEST: get pointer to FPU globals
            Value *globalTag = getGlobalRegAsPtr(B, FPU_TAG);
            // SIZE: 8 entries * sizeof(Int2Ty)
            // Volatile = FALSE
            uint32_t tags_arr_size =
                (uint32_t)td.getTypeAllocSize(
                        Type::getIntNTy(B->getContext(), 2)) * NUM_FPU_REGS;

			Instruction *mcp = aliasMCSemaScope(callMemcpy(B, globalTag, localTag, tags_arr_size, 4, false));

			// last IP segment is a 16-bit value
            STORE_F(FPU_LASTIP_SEG);
            // 32-bit register not in X86 Namespace
            STORE_SAMEWIDTH(FPU_LASTIP_OFF);
            // last data segment is a 16-bit value
            STORE_F(FPU_LASTDATA_SEG);
            // 32-bit register not in X86 Namespace
            STORE_SAMEWIDTH(FPU_LASTDATA_OFF);

           // STORE_F(FPU_FOPCODE);

            //vector instrs
            STORE_SAMEWIDTH(XMM0);
            STORE_SAMEWIDTH(XMM1);
            STORE_SAMEWIDTH(XMM2);
            STORE_SAMEWIDTH(XMM3);
            STORE_SAMEWIDTH(XMM4);
            STORE_SAMEWIDTH(XMM5);
            STORE_SAMEWIDTH(XMM6);
            STORE_SAMEWIDTH(XMM7);
			STORE_SAMEWIDTH(XMM8);
			STORE_SAMEWIDTH(XMM9);
			STORE_SAMEWIDTH(XMM10);
			STORE_SAMEWIDTH(XMM11);
			STORE_SAMEWIDTH(XMM12);
			STORE_SAMEWIDTH(XMM13);
			STORE_SAMEWIDTH(XMM14);
			STORE_SAMEWIDTH(XMM15);


            // stack base and limit
            STORE_SAMEWIDTH(STACK_BASE);
            STORE_SAMEWIDTH(STACK_LIMIT);
        }
#undef STORE
		break;
        default:
          throw TErr(__LINE__, __FILE__, to_string<unsigned>(bits, dec)+"-bit not implemented yet");
    }

    return;
}

void writeContextToLocals(BasicBlock *B, unsigned bits, StoreSpillType whichRegs) {
    Function    *F = B->getParent();
    //lookup the argument value to this function
    TASSERT(F->arg_size() >= 1, "need at least one argument to write context to locals");
    Value       *arg = F->arg_begin();

    //there are a few occasions where we have to take the entirety of a
    //context structure and 'spill' them to locally allocated values
    switch(bits) {
        case 32:
        {
            //UPDATEREGS -- when we add something to the 'regs' struct change
            //here to reflect that
            //do a GEP on the 'regs' structure for the appropriate field offset
            //then do a 'load' from that GEP into a temp and then a
            //'store' into the appropriate value
#define SPILL_F_N(nm, nbits) { \
        std::string regnm = x86::getRegisterName(nm);\
		Value   *localVal = x86::lookupLocal(F, nm); \
                 if( localVal == NULL ) \
                  throw TErr(__LINE__, __FILE__, "Could not find val"+regnm); \
                int     off = x86::getRegisterOffset(nm); \
                Value   *GEPV[] =  \
                    { ConstantInt::get(Type::getInt32Ty(B->getContext()), 0), \
                    ConstantInt::get(Type::getInt32Ty(B->getContext()), off)}; \
                Instruction *GEP = GetElementPtrInst::CreateInBounds(arg, \
                    GEPV, regnm, B); \
                LoadInst *li = new LoadInst(GEP, "", B);\
                if(nbits != 32) {\
                    li->setAlignment(1);\
                }\
                Instruction   *T = aliasMCSemaScope(li); \
                Value   *truncI  = NULL; \
                if(!T->getType()->isIntegerTy(nbits)) \
                { \
                    truncI = new TruncInst(T, Type::getIntNTy(B->getContext(), nbits), "", B); \
                } \
                else  \
                { \
                    truncI = T; \
                }\
                Instruction *W = aliasMCSemaScope(new StoreInst(truncI, localVal, B)); \
                TASSERT( W != NULL, "" ); \
            }

#define SPILL_F(nm) SPILL_F_N(nm, 1)
#define SPILL(nm) SPILL_F_N(nm, 32)

            SPILL(EAX);
            SPILL(EBX);
            SPILL(ECX);
            SPILL(EDX);
            SPILL(ESI);
            SPILL(EDI);
            SPILL(ESP);
            SPILL(EBP);


            SPILL_F(CF);
            SPILL_F(PF);
            SPILL_F(AF);
            SPILL_F(ZF);
            SPILL_F(SF);
            SPILL_F(OF);
            SPILL_F(DF);

            //use llvm.memcpy to copy locals to context
            // SOURCE: get pointer to FPU globals
            Value *globalFPU = getGlobalFPURegsAsPtr(B);
            // DEST: get pointer to FPU locals
            Value *localFPU = getLocalFPURegsAsPtr(B);
            // SIZE: 8 registers sizeof(fp type)
            // ALIGN = 4
            // Volatile = FALSE
            DataLayout  td(F->getParent());
            uint32_t fpu_arr_size =
                (uint32_t)td.getTypeAllocSize(Type::getX86_FP80Ty(B->getContext())) * NUM_FPU_REGS;

            Instruction *mcp_fpu = aliasMCSemaScope(callMemcpy(B, localFPU, globalFPU, fpu_arr_size, 8, false));

            // time for FPU Flags
            SPILL_F(FPU_B);
            SPILL_F(FPU_C3);
            // TOP is a 3-bit integer and not
            // a one bit flag
            SPILL_F_N(FPU_TOP, 3);
            SPILL_F(FPU_C2);
            SPILL_F(FPU_C1);
            SPILL_F(FPU_C0);
            SPILL_F(FPU_ES);
            SPILL_F(FPU_SF);
            SPILL_F(FPU_PE);
            SPILL_F(FPU_UE);
            SPILL_F(FPU_OE);
            SPILL_F(FPU_ZE);
            SPILL_F(FPU_DE);
            SPILL_F(FPU_IE);

            // FPU CONTROL WORD
            SPILL_F(FPU_X);
            SPILL_F_N(FPU_RC, 2);
            SPILL_F_N(FPU_PC, 2);
            SPILL_F(FPU_PM);
            SPILL_F(FPU_UM);
            SPILL_F(FPU_OM);
            SPILL_F(FPU_ZM);
            SPILL_F(FPU_DM);
            SPILL_F(FPU_IM);

            // DEST: get pointer to local tag word
            Value *localTag = getLocalRegAsPtr(B, FPU_TAG);
            // SRC: get pointer to FPU globals
            Value *globalTag = getGlobalRegAsPtr(B, FPU_TAG);
            // SIZE: 8 entries * sizeof(Int2Ty)
            // ALIGN = 4
            // Volatile = FALSE
            uint32_t tags_arr_size =
                (uint32_t)td.getTypeAllocSize(
                        Type::getIntNTy(B->getContext(), 2)) * NUM_FPU_REGS;

            Instruction *mcp_tag = aliasMCSemaScope(callMemcpy(B, localTag, globalTag, tags_arr_size, 4, false));

            // fpu last instruction ptr
            SPILL_F_N(FPU_LASTIP_SEG, 16);
            SPILL(FPU_LASTIP_OFF);
            // fpu last data ptr
            SPILL_F_N(FPU_LASTDATA_SEG, 16);
            SPILL(FPU_LASTDATA_OFF);

            // last FPU opcode
            SPILL_F_N(FPU_FOPCODE, 11);

            //write vector regs out
            SPILL_F_N(XMM0, 128);
            SPILL_F_N(XMM1, 128);
            SPILL_F_N(XMM2, 128);
            SPILL_F_N(XMM3, 128);
            SPILL_F_N(XMM4, 128);
            SPILL_F_N(XMM5, 128);
            SPILL_F_N(XMM6, 128);
            SPILL_F_N(XMM7, 128);

            // stack base and limit
            SPILL(STACK_BASE);
            SPILL(STACK_LIMIT);
        }
            break;
#undef SPILL_F_N
#undef SPILL_F
#undef SPILL

        case 64:
		{
#define SPILL_F_N(nm, nbits) { \
std::string regnm = x86_64::getRegisterName(nm); \
		Value   *localVal = x86_64::lookupLocal(F, nm); \
		if( localVal == NULL ) \
			throw TErr(__LINE__, __FILE__, "Could not find val"+regnm); \
		int     off = x86_64::getRegisterOffset(nm); \
		Value   *GEPV[] =  \
			{ ConstantInt::get(Type::getInt64Ty(B->getContext()), 0), \
			ConstantInt::get(Type::getInt32Ty(B->getContext()), off)}; \
		Instruction *GEP = GetElementPtrInst::CreateInBounds(arg, \
                    GEPV, regnm, B); \
		LoadInst *li = new LoadInst(GEP, "", B);\
		if(nbits != 64) {\
			li->setAlignment(1);\
		}\
		Instruction   *T = aliasMCSemaScope(li); \
		Value   *truncI  = NULL; \
		if(!T->getType()->isIntegerTy(nbits)) \
		{ \
			truncI = new TruncInst(T, Type::getIntNTy(B->getContext(), nbits), "", B); \
		} \
		else  \
		{ \
			truncI = T; \
		}\
		Instruction *W = aliasMCSemaScope(new StoreInst(truncI, localVal, B)); \
		TASSERT( W != NULL, "" ); \
		}

#define SPILL_F(nm) SPILL_F_N(nm, 1)
#define SPILL(nm) SPILL_F_N(nm, 64)

            SPILL(RAX);
            SPILL(RBX);
            SPILL(RCX);
            SPILL(RDX);
            SPILL(RSI);
            SPILL(RDI);
            SPILL(RSP);
            SPILL(RBP);

            SPILL(R8);
            SPILL(R9);
            SPILL(R10);
            SPILL(R11);
            SPILL(R12);
            SPILL(R13);
            SPILL(R14);
            SPILL(R15);
            SPILL(RIP);

            SPILL_F(CF);
            SPILL_F(PF);
            SPILL_F(AF);
            SPILL_F(ZF);
            SPILL_F(SF);
            SPILL_F(OF);
            SPILL_F(DF);

            // FPU registers doesn't get used on 64bit platform;
			// we are not spilling them

			            // SOURCE: get pointer to FPU globals
            Value *globalFPU = getGlobalFPURegsAsPtr(B);
            // DEST: get pointer to FPU locals
            Value *localFPU = getLocalFPURegsAsPtr(B);
            // Volatile = FALSE
            DataLayout  td(F->getParent());
            uint32_t fpu_arr_size =
                (uint32_t)td.getTypeAllocSize(Type::getX86_FP80Ty(B->getContext())) * NUM_FPU_REGS;

            Instruction *mcp_fpu = aliasMCSemaScope(callMemcpy(B, localFPU, globalFPU, fpu_arr_size, 4, false));

            SPILL_F(FPU_B);
            SPILL_F(FPU_C3);
            // TOP is a 3-bit integer and not
            // a one bit flag
            SPILL_F_N(FPU_TOP, 3);
            SPILL_F(FPU_C2);
            SPILL_F(FPU_C1);
            SPILL_F(FPU_C0);
            SPILL_F(FPU_ES);
            SPILL_F(FPU_SF);
            SPILL_F(FPU_PE);
            SPILL_F(FPU_UE);
            SPILL_F(FPU_OE);
            SPILL_F(FPU_ZE);
            SPILL_F(FPU_DE);
            SPILL_F(FPU_IE);

			// FPU CONTROL WORD
            SPILL_F(FPU_X);
            SPILL_F_N(FPU_RC, 2);
            SPILL_F_N(FPU_PC, 2);
            SPILL_F(FPU_PM);
            SPILL_F(FPU_UM);
            SPILL_F(FPU_OM);
            SPILL_F(FPU_ZM);
            SPILL_F(FPU_DM);
            SPILL_F(FPU_IM);

            // DEST: get pointer to local tag word
            Value *localTag = getLocalRegAsPtr(B, FPU_TAG);
            // SRC: get pointer to FPU globals
            Value *globalTag = getGlobalRegAsPtr(B, FPU_TAG);
            // SIZE: 8 entries * sizeof(Int2Ty)
            // ALIGN = 4
            // Volatile = FALSE
            uint32_t tags_arr_size =
                (uint32_t)td.getTypeAllocSize(
                        Type::getIntNTy(B->getContext(), 2)) * NUM_FPU_REGS;

            Instruction *mcp_tag = aliasMCSemaScope(callMemcpy(B, localTag, globalTag, tags_arr_size, 4, false));

			// fpu last instruction ptr
            SPILL_F_N(FPU_LASTIP_SEG, 16);
            SPILL_F_N(FPU_LASTIP_OFF, 64);
            // fpu last data ptr
			SPILL_F_N(FPU_LASTDATA_SEG, 16);
			SPILL_F_N(FPU_LASTDATA_OFF, 64);

            // last FPU opcode
			SPILL_F_N(FPU_FOPCODE, 11);

            //write vector regs out
            SPILL_F_N(XMM0, 128);
            SPILL_F_N(XMM1, 128);
            SPILL_F_N(XMM2, 128);
            SPILL_F_N(XMM3, 128);
            SPILL_F_N(XMM4, 128);
            SPILL_F_N(XMM5, 128);
            SPILL_F_N(XMM6, 128);
            SPILL_F_N(XMM7, 128);
			SPILL_F_N(XMM8, 128);
			SPILL_F_N(XMM9, 128);
			SPILL_F_N(XMM10, 128);
			SPILL_F_N(XMM11, 128);
			SPILL_F_N(XMM12, 128);
			SPILL_F_N(XMM13, 128);
			SPILL_F_N(XMM14, 128);
			SPILL_F_N(XMM15, 128);

            // stack base and limit
            SPILL(STACK_BASE);
            SPILL(STACK_LIMIT);
        }
#undef SPILL_F
#undef SPILL
            break;

        default:
          throw TErr(__LINE__, __FILE__, to_string<unsigned>(bits, dec)+"-bit not implemented yet");
    }
    return;
}

namespace x86
{
}

using namespace x86;


// do any instruction preprocessing/conversion
// before moving on to translation.
// currently used to turn non-conforming jump talbles
// into data sections
//
static void preprocessInstruction(
        NativeModulePtr   natM,
        BasicBlock        *&block,
        InstPtr           ip,
        MCInst            &inst
        )
{

    // only add data sections for non-conformant jump tables
    //
    // the conformant tables are handled in the instruction
    // translator via switch()
    if(ip->has_jump_table() )
    {
        if(!isConformantJumpInst(ip)) {
            {
                llvm::dbgs() << "WARNING: jump table but non-conformant instruction:\n";
                llvm::dbgs() << to_string<VA>(ip->get_loc(), hex) << ": ";
                llvm::dbgs () << inst << "\n";

                VA tbl_va;
                MCSJumpTablePtr jmptbl = ip->get_jump_table();

                bool ok = addJumpTableDataSection(
                        natM,
                        block->getParent()->getParent(),
                        tbl_va,
                        *jmptbl);

                TASSERT(ok, "Could not add jump table data section!\n");

                uint32_t data_ref_va =
                    static_cast<uint32_t>(tbl_va + 4*jmptbl->getInitialEntry());

                ip->set_reference(Inst::MEMRef, data_ref_va);
                ip->set_ref_type(Inst::MEMRef, Inst::CFGDataRef);
            }

        }
    }
    // only add data references for unknown jump index table
    // reads
    else if(ip->has_jump_index_table() &&
            inst.getOpcode() != X86::MOVZX32rm8)
    {

        VA idx_va;
        JumpIndexTablePtr idxtbl = ip->get_jump_index_table();

        bool ok = addJumpIndexTableDataSection(
                natM,
                block->getParent()->getParent(),
                idx_va,
                *idxtbl);

        TASSERT(ok, "Could not add jump index table data section!\n");

        uint32_t data_ref_va =
            static_cast<uint32_t>(idx_va + idxtbl->getInitialEntry());

        ip->set_reference(Inst::MEMRef, data_ref_va);
        ip->set_ref_type(Inst::MEMRef, Inst::CFGDataRef);
    }

}

// Take the supplied MCInst and turn it into a series of LLVM instructions.
// Insert those instructions into the supplied block.
// Here's the philosophy:
// LLVM MCInst opcodes encode X86 instructions by, roughly:
//
//    mnemonic[bitwidth]<operandlist>
//
//  So for example, there are many different encodings and bitwidths of the
//  "add" mnemonic. each combination has its own space in the opcodes enum
//
//  We're narrowing from the space of LLVM MCInst opcodes in a few steps:
//     1. First by width. we take each mnemonic and classify it by width.
//        there are templated functions for dealing with mnemonic / operand
//        pairs, parameterized around operand width
//     2. next by operand type. Within each parameterized wrapper, we
//        'unrwrap' by extracting each operand and producing input values
//        to the instructions
//     3. finally, in an inner step, we define the instruction semantics
//        entirely in terms of LLVM Value objects. This is where the 'meat'
//        of semantic modeling takes places.
//     The breakdown looks something like this:
//
//     X86::CMP8rr -> [1] -> doCmpRR<8> -> [2] doCmpVV<8> -> [3]
//
//     The innermost is where most of the intelligent decisions happen.
//
InstTransResult disInstrX86(    InstPtr           ip,
                                BasicBlock        *&block,
                                NativeBlockPtr    nb,
                                Function          *F,
                                NativeFunctionPtr natF,
                                NativeModulePtr   natM)
{
    MCInst              inst = ip->get_inst();
    InstTransResult     itr = ContinueBlock;
    string              outS;
    raw_string_ostream  strOut(outS);
    MCInstPrinter       *IP = nb->get_printer();

    if (IP == NULL)
      throw TErr(__LINE__, __FILE__, "No instruction printer supplied with native block");

    // For conditional instructions, get the "true" and "false" targets.
    // This will also look up the target for nonconditional jumps.
    //string trueStrName = "block_0x" + to_string<VA>(ip->get_tr(), hex);
    //string falseStrName = "block_0x" + to_string<VA>(ip->get_fa(), hex);

    TranslationFuncPtr translationPtr;

    unsigned opcode = inst.getOpcode();
    if (translationDispatchMap.find(opcode) != translationDispatchMap.end()) {
        // Instruction translation defined.
        translationPtr = translationDispatchMap[opcode];
        preprocessInstruction(natM, block, ip, inst);
        itr = translationPtr(natM, block, ip, inst);
    } else {
        // Instruction translation not defined.
        errs() << "Unsupported!\n";
        // Print out the unhandled opcode.
        errs() << to_string<VA>(ip->get_loc(), hex) << " ";
        IP->printInst(&inst, strOut, "");
        errs() << strOut.str() << "\n";
        errs() << inst.getOpcode() << "\n";
        if (X86::REP_PREFIX != opcode && X86::REPNE_PREFIX != opcode) {
            itr = TranslateErrorUnsupported;
        } else {
            errs() << "Unsupported instruction is a rep/repne, trying to skip to next instr.\n";
        }
    }
    //D(cout << __FUNCTION__ << " : " << opcode << "\n";
    //cout.flush();)
    return itr;
}

#undef OP
