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

#include "JumpTables.h"

#include "x86Helpers.h"
#include "x86Instrs_fpu.h"
#include "x86Instrs_MOV.h"
#include "InstructionDispatch.h"
#include "llvm/IR/DataLayout.h"
#include "x86Instrs_flagops.h"
#include "../common/to_string.h"

using namespace std;
using namespace llvm;

Value* getGlobalRegAsPtr(BasicBlock *B, string regName)
{
    Function *F = B->getParent();
    Value *arg = F->arg_begin();
    int globalRegsOff = mapStrToGEPOff(regName); 
    Value *globalGlobalGEPV[] = {
        CONST_V<32>(B, 0),
        CONST_V<32>(B, globalRegsOff),
        CONST_V<32>(B, 0) };

    // Get element pointer.
    Instruction *gGlobalPtr = GetElementPtrInst::CreateInBounds(arg, globalGlobalGEPV, "", B);
    // Cast pointer to int8* for use with memcpy.
    Instruction *globalCastPtr = CastInst::CreatePointerCast(
        gGlobalPtr, Type::getInt8PtrTy(B->getContext()), "", B);

    return globalCastPtr;
}

Value* getGlobalFPURegsAsPtr(BasicBlock *B)
{
    return getGlobalRegAsPtr(B, "ST0");
}

Value* getLocalRegAsPtr(BasicBlock *B, string regName)
{
    Function *F = B->getParent();

    Value *localReg = lookupLocalByName(F, regName);

    // Need to get pointer to array[0] via GEP.
    Value *localGEP[] = {
        CONST_V<32>(B, 0),
        CONST_V<32>(B, 0)};
    Instruction *localPtr = GetElementPtrInst::CreateInBounds(
        localReg, localGEP, "", B);

    // Cast pointer to an Int8* for use with memcpy.
    Instruction *localCastPtr = CastInst::CreatePointerCast(
            localPtr, Type::getInt8PtrTy(B->getContext()), "", B);

    return localCastPtr;
}

Value* getLocalFPURegsAsPtr(BasicBlock *B)
{
    return getLocalRegAsPtr(B, "STi_val");
}

void writeLocalsToContext(BasicBlock *B, unsigned bits)
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
            Value   *localVal = lookupLocalByName(F, nm+"_val");\
            if (localVal == NULL)\
              throw TErr(__LINE__, __FILE__, "Could not find val"+nm);\
            int eaxOff = mapStrToGEPOff(nm);\
            Value *eaxGEPV[] =\
                { ConstantInt::get(Type::getInt32Ty(B->getContext()), 0),\
                ConstantInt::get(Type::getInt32Ty(B->getContext()), eaxOff)};\
            Instruction *eaxGEP = GetElementPtrInst::CreateInBounds(arg,\
                eaxGEPV, nm, B);\
            Value *loadedVal = R_READ<32>(B, nm_in);\
            Value *eaxT = new StoreInst(loadedVal, eaxGEP, B);\
            TASSERT(eaxT != NULL, "");\
            }
            STORE(string("EAX"), X86::EAX);
            STORE(string("EBX"), X86::EBX);
            STORE(string("ECX"), X86::ECX);
            STORE(string("EDX"), X86::EDX);
            STORE(string("ESI"), X86::ESI);
            STORE(string("EDI"), X86::EDI);
            STORE(string("ESP"), X86::ESP);
            STORE(string("EBP"), X86::EBP);
#define STORE_SAMEWIDTH(nm) { \
            Value   *localVal = lookupLocalByName(F, nm+"_val"); \
            if( localVal == NULL ) \
              throw TErr(__LINE__, __FILE__, "Could not find val"+nm); \
            int off = mapStrToGEPOff(nm); \
            Value   *GEPV[] =  \
                { ConstantInt::get(Type::getInt32Ty(B->getContext()), 0), \
                ConstantInt::get(Type::getInt32Ty(B->getContext()), off)}; \
            Instruction *GEP = GetElementPtrInst::CreateInBounds(arg, \
                GEPV, nm, B); \
            Value   *loadedVal = GENERIC_READREG(B, nm); \
            Value   *st = new StoreInst(loadedVal, GEP, B); \
            TASSERT(st != NULL, "" ); \
        }
#define STORE_F(nm) STORE_SAMEWIDTH(nm)
/*
{ \
            Value   *localVal = lookupLocalByName(F, nm+"_val"); \
            if( localVal == NULL ) \
              throw TErr(__LINE__, __FILE__, "Could not find val"+nm); \
            int off = mapStrToGEPOff(nm); \
            Value   *GEPV[] =  \
                { ConstantInt::get(Type::getInt32Ty(B->getContext()), 0), \
                ConstantInt::get(Type::getInt32Ty(B->getContext()), off)}; \
            Instruction *GEP = GetElementPtrInst::CreateInBounds(arg, \
                GEPV, nm, B); \
            Value   *loadedVal = F_READ(B, nm); \
            Value   *st = new StoreInst(loadedVal, GEP, B); \
            TASSERT(st != NULL, "" ); \
        }
// Value   *extendedVal = new ZExtInst(loadedVal, Type::getInt32Ty(B->getContext()), "", B); \
    //Value   *st = new StoreInst(extendedVal, GEP, B); \
*/

            STORE_F(string("CF"));
            STORE_F(string("PF"));
            STORE_F(string("AF"));
            STORE_F(string("ZF"));
            STORE_F(string("SF"));
            STORE_F(string("OF"));
            STORE_F(string("DF"));

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

            callMemcpy(B, globalFPU, localFPU, fpu_arr_size, 4, false);

            STORE_F(string("FPU_B"));
            STORE_F(string("FPU_C3"));
            // TOP is a 3-bit integer and not
            // a one bit flag, but STORE_F
            // just zero-extends and writes to
            // a 32-bit integer.
            STORE_F(string("FPU_TOP"));
            STORE_F(string("FPU_C2"));
            STORE_F(string("FPU_C1"));
            STORE_F(string("FPU_C0"));
            STORE_F(string("FPU_ES"));
            STORE_F(string("FPU_SF"));
            STORE_F(string("FPU_PE"));
            STORE_F(string("FPU_UE"));
            STORE_F(string("FPU_OE"));
            STORE_F(string("FPU_ZE"));
            STORE_F(string("FPU_DE"));
            STORE_F(string("FPU_IE"));

            // FPU CONTROL FLAGS
            STORE_F(string("FPU_X" ));
            STORE_F(string("FPU_RC"));
            STORE_F(string("FPU_PC"));
            STORE_F(string("FPU_PM"));
            STORE_F(string("FPU_UM"));
            STORE_F(string("FPU_OM"));
            STORE_F(string("FPU_ZM"));
            STORE_F(string("FPU_DM"));
            STORE_F(string("FPU_IM"));

            // SOURCE: get pointer to local tag word
            Value *localTag = getLocalRegAsPtr(B, "FPU_TAG_val");
            // DEST: get pointer to FPU globals
            Value *globalTag = getGlobalRegAsPtr(B, "FPU_TAG");
            // SIZE: 8 entries * sizeof(Int2Ty)
            // ALIGN = 4
            // Volatile = FALSE
            uint32_t tags_arr_size = 
                (uint32_t)td.getTypeAllocSize(
                        Type::getIntNTy(B->getContext(), 2)) * NUM_FPU_REGS;

            callMemcpy(B, globalTag, localTag, tags_arr_size, 4, false);

            // last IP segment is a 16-bit value
            STORE_F(string("FPU_LASTIP_SEG"));
            // 32-bit register not in X86 Namespace
            STORE_SAMEWIDTH(string("FPU_LASTIP_OFF"));
            // last data segment is a 16-bit value
            STORE_F(string("FPU_LASTDATA_SEG"));
            // 32-bit register not in X86 Namespace
            STORE_SAMEWIDTH(string("FPU_LASTDATA_OFF"));

            STORE_F(string("FPU_FOPCODE"));

            //vector instrs
            STORE_SAMEWIDTH(string("XMM0"));
            STORE_SAMEWIDTH(string("XMM1"));
            STORE_SAMEWIDTH(string("XMM2"));
            STORE_SAMEWIDTH(string("XMM3"));
            STORE_SAMEWIDTH(string("XMM4"));
            STORE_SAMEWIDTH(string("XMM5"));
            STORE_SAMEWIDTH(string("XMM6"));
            STORE_SAMEWIDTH(string("XMM7"));

            // stack base and limit
            STORE_SAMEWIDTH(string("STACK_BASE"));
            STORE_SAMEWIDTH(string("STACK_LIMIT"));
        }
        break;

        default:
          throw TErr(__LINE__, __FILE__, to_string<unsigned>(bits, dec)+"-bit not implemented yet");
    }
 
    return;
}
#undef STORE

void writeContextToLocals(BasicBlock *B, unsigned bits) {
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
            Value   *localVal = lookupLocalByName(F, nm+"_val"); \
             if( localVal == NULL ) \
              throw TErr(__LINE__, __FILE__, "Could not find val"+nm); \
            int     off = mapStrToGEPOff(nm); \
            Value   *GEPV[] =  \
                { ConstantInt::get(Type::getInt32Ty(B->getContext()), 0), \
                ConstantInt::get(Type::getInt32Ty(B->getContext()), off)}; \
            Instruction *GEP = GetElementPtrInst::CreateInBounds(arg, \
                GEPV, nm, B); \
            Value   *T = new LoadInst(GEP, "", B); \
            Value   *truncI  = NULL; \
            if(! T->getType()->isIntegerTy(nbits)) \
            { \
                truncI = new TruncInst(T, Type::getIntNTy(B->getContext(), nbits), "", B); \
            } \
            else  \
            { \
                truncI = T; \
            }\
            Instruction *W = new StoreInst(truncI, localVal, B); \
            TASSERT( W != NULL, "" ); \
            }

#define SPILL_F(nm) SPILL_F_N(nm, 1)
#define SPILL(nm) SPILL_F_N(nm, 32)

            SPILL(string("EAX"));
            SPILL(string("EBX"));
            SPILL(string("ECX"));
            SPILL(string("EDX"));
            SPILL(string("ESI"));
            SPILL(string("EDI"));
            SPILL(string("ESP"));
            SPILL(string("EBP"));


            SPILL_F(string("CF"));
            SPILL_F(string("PF"));
            SPILL_F(string("AF"));
            SPILL_F(string("ZF"));
            SPILL_F(string("SF"));
            SPILL_F(string("OF"));
            SPILL_F(string("DF"));

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

            callMemcpy(B, localFPU, globalFPU, fpu_arr_size, 4, false);

            // time for FPU Flags
            SPILL_F(string("FPU_B"));
            SPILL_F(string("FPU_C3"));
            // TOP is a 3-bit integer and not
            // a one bit flag 
            SPILL_F_N(string("FPU_TOP"), 3);
            SPILL_F(string("FPU_C2"));
            SPILL_F(string("FPU_C1"));
            SPILL_F(string("FPU_C0"));
            SPILL_F(string("FPU_ES"));
            SPILL_F(string("FPU_SF"));
            SPILL_F(string("FPU_PE"));
            SPILL_F(string("FPU_UE"));
            SPILL_F(string("FPU_OE"));
            SPILL_F(string("FPU_ZE"));
            SPILL_F(string("FPU_DE"));
            SPILL_F(string("FPU_IE"));

            // FPU CONTROL WORD
            SPILL_F(string("FPU_X" ));
            SPILL_F_N(string("FPU_RC"), 2);
            SPILL_F_N(string("FPU_PC"), 2);
            SPILL_F(string("FPU_PM"));
            SPILL_F(string("FPU_UM"));
            SPILL_F(string("FPU_OM"));
            SPILL_F(string("FPU_ZM"));
            SPILL_F(string("FPU_DM"));
            SPILL_F(string("FPU_IM"));

            // DEST: get pointer to local tag word
            Value *localTag = getLocalRegAsPtr(B, "FPU_TAG_val");
            // SRC: get pointer to FPU globals
            Value *globalTag = getGlobalRegAsPtr(B, "FPU_TAG");
            // SIZE: 8 entries * sizeof(Int2Ty)
            // ALIGN = 4
            // Volatile = FALSE
            uint32_t tags_arr_size = 
                (uint32_t)td.getTypeAllocSize(
                        Type::getIntNTy(B->getContext(), 2)) * NUM_FPU_REGS;

            callMemcpy(B, localTag, globalTag, tags_arr_size, 4, false);

            // fpu last instruction ptr
            SPILL_F_N(string("FPU_LASTIP_SEG"), 16);
            SPILL(string("FPU_LASTIP_OFF"));
            // fpu last data ptr
            SPILL_F_N(string("FPU_LASTDATA_SEG"), 16);
            SPILL(string("FPU_LASTDATA_OFF"));

            // last FPU opcode
            SPILL_F_N(string("FPU_FOPCODE"), 11);

            //write vector regs out
            SPILL_F_N(string("XMM0"), 128);
            SPILL_F_N(string("XMM1"), 128);
            SPILL_F_N(string("XMM2"), 128);
            SPILL_F_N(string("XMM3"), 128);
            SPILL_F_N(string("XMM4"), 128);
            SPILL_F_N(string("XMM5"), 128);
            SPILL_F_N(string("XMM6"), 128);
            SPILL_F_N(string("XMM7"), 128);

            // stack base and limit
            SPILL(string("STACK_BASE"));
            SPILL(string("STACK_LIMIT"));
        }
            break;

        case 64:
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
    if(ip->has_jump_table() && !isConformantJumpInst(ip)) {

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

        ip->set_data_offset(data_ref_va);

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

        ip->set_data_offset(data_ref_va);
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
        itr = TranslateErrorUnsupported;
    }
    return itr;
}
 
#undef OP
