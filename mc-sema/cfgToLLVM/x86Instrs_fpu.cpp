/*
Copyright (c) 2014, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of Trail of Bits nor the names of its
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

#include "x86Helpers.h"
#include "x86Instrs_fpu.h"
#include "InstructionDispatch.h"
#include "RegisterUsage.h"

#include <vector>
#include <cmath>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#define M_LN2 0.693147180559945309417
#define M_LOG10E 0.434294481903251827651
#define M_LOG2E 1.44269504088896340736
#endif

#define M_FLDLG2 0.301029995663981195214

#define NASSERT(cond) TASSERT(cond, "")

#define MAKEWORD(x, y) (((x) << 8) | (y))
#define MAKE_FOPCODE(x, y) (MAKEWORD(x, y) & 0x7FF)

using namespace llvm;

static Value* ADDR_TO_POINTER_V(BasicBlock *b, Value *memAddr, Type *ptrType)
{
    if (memAddr->getType()->isPointerTy() == false)
    {
        // its an integer, make it a pointer
        return new llvm::IntToPtrInst(memAddr, ptrType , "", b);
    }
    else if (memAddr->getType() != ptrType)
    {
        // its a pointer, but of the wrong type
        return CastInst::CreatePointerCast(memAddr, ptrType, "", b);
    } else {
        // already correct ptr type
        return memAddr;
    }
}

template <int width>
static Value* ADDR_TO_POINTER(BasicBlock *b, Value *memAddr)
{
    NASSERT(memAddr != NULL);
    llvm::Type *ptrType = Type::getIntNPtrTy(b->getContext(), width);
    return ADDR_TO_POINTER_V(b, memAddr, ptrType);
}

template <int width>
static Value *SHL_NOTXOR_V(llvm::BasicBlock *block, Value *val,
    Value *val_to_shift, int shlbits)
{
    Value *fv = val_to_shift;
    Value *nfv = llvm::BinaryOperator::CreateNot(fv, "", block);
    Value *nzfv = new llvm::ZExtInst(nfv, llvm::Type::getIntNTy(
        block->getContext(), width), "", block);
    Value *shl = llvm::BinaryOperator::CreateShl(
        nzfv, CONST_V<width>(block, shlbits), "", block);
    Value *anded = llvm::BinaryOperator::CreateXor(shl, val, "", block);

    return anded;
}

template <int width>
static Value *SHL_NOTXOR_FLAG(llvm::BasicBlock *block, Value *val,
    MCSemaRegs flag, int shlbits)
{
    Value *fv = F_READ(block, flag);
    return SHL_NOTXOR_V<width>(block, val, fv, shlbits);
}


static void SET_FPU_FOPCODE(BasicBlock *&b, uint8_t opcode[4])
{
    //assume we will never set fopcode
    //uint16_t op = MAKE_FOPCODE(opcode[0], opcode[1]);
    //Value *op_v = CONST_V<11>(b, op);
    //F_WRITE(b, FPU_FOPCODE, op_v);
    return;
}

static void setFpuDataPtr(BasicBlock *&b, Value *dataptr)
{
    // assume no FPU data
    //Value *addrInt = new PtrToIntInst(
    //    dataptr, llvm::Type::getInt32Ty(b->getContext()), "", b);
    //F_WRITE(b, FPU_LASTDATA_OFF, addrInt);
    return;
}

static void setFpuInstPtr(llvm::BasicBlock *&b, llvm::BasicBlock *addr_to_take)
{
    // ***WARNING***
    // in LLVM 3.0 BlockAddress arguments *break* the JIT.
    // The JITter will not emit the operand portion of an instruction that
    // stores the value, making the rest of the instruction stream off by 4
    // 4 bytes.
    //Value *bbaddr = BlockAddress::get(addr_to_take);
    //Value *addrInt = new PtrToIntInst(
    //    bbaddr, llvm::Type::getInt32Ty(b->getContext()), "", b);

    // For now we store a constant 0 until a solution is found to store the
    // real value.
    //Value *addrInt = CONST_V<32>(b, 0);
    //F_WRITE(b, FPU_LASTIP_OFF, addrInt);
    // assume no fpu last ip
    return;
}

static void setFpuInstPtr(llvm::BasicBlock *b)
{
    return setFpuInstPtr(b, b);
}

#if 1
static Value* adjustFpuPrecision(BasicBlock *&b, Value *fpuval)
{
    return fpuval;
}
#else
static Value* adjustFpuPrecision(BasicBlock *&b, Value *fpuval)
{
    // We only expect to be called on native FPU types that need to be
    // adjusted.
    NASSERT(fpuval->getType()->isX86_FP80Ty());

    // Read precision flag.
    // switch (pc)
    // case 0: single precision
    // case 2: double precision
    // default: double extended (native x86)

    Value *pc = F_READ(b, FPU_PC);

    CREATE_BLOCK(native_precision, b);
    CREATE_BLOCK(single_precision, b);
    CREATE_BLOCK(double_precision, b);
    CREATE_BLOCK(done_adjusting, b);

    SwitchInst *pcSwitch = SwitchInst::Create(pc, block_native_precision, 3, b);
    pcSwitch->addCase(CONST_V<2>(b, 0), block_single_precision);
    pcSwitch->addCase(CONST_V<2>(b, 2), block_double_precision);
    pcSwitch->addCase(CONST_V<2>(b, 3), block_native_precision);

    // Populate native block - no adjustment needed.
    BranchInst::Create(block_done_adjusting, block_native_precision);

    // Populate single precision - convert to single precision type,
    // convert back to native precision, return.
    Value *singlep = new FPTruncInst(fpuval,
        llvm::Type::getFloatTy(block_single_precision->getContext()),
        "", block_single_precision);
    Value *single_ton = new FPExtInst(singlep,
        llvm::Type::getX86_FP80Ty(block_single_precision->getContext()),
        "", block_single_precision);
    BranchInst::Create(block_done_adjusting, block_single_precision);

    // Populate double precision - convert to double and then back to native.
    Value *doublep = new FPTruncInst(fpuval,
        llvm::Type::getDoubleTy(block_double_precision->getContext()),
        "", block_double_precision);
    Value *double_ton = new FPExtInst(doublep,
        llvm::Type::getX86_FP80Ty(block_double_precision->getContext()),
        "", block_double_precision);
    BranchInst::Create(block_done_adjusting, block_double_precision);

    // Populate done_adjusting block.
    PHINode *adjustedVal =
        PHINode::Create(Type::getX86_FP80Ty(block_done_adjusting->getContext()),
                        3,
                        "fpu_precision_adjust",
                        block_done_adjusting);

    adjustedVal->addIncoming(fpuval, block_native_precision);
    adjustedVal->addIncoming(single_ton, block_single_precision);
    adjustedVal->addIncoming(double_ton, block_double_precision);

    b = block_done_adjusting;
    return adjustedVal;
}
#endif

static void FPUF_SET(BasicBlock *&b, MCSemaRegs reg)
{
    F_WRITE(b, reg, CONST_V<1>(b, 1));
    return;
}

static void FPUF_CLEAR(BasicBlock *&b, MCSemaRegs reg)
{
    F_WRITE(b, reg, CONST_V<1>(b, 0));
    return;
}

static Value * CONSTFP_V(BasicBlock *&b, long double val)
{
    llvm::Type *bTy = llvm::Type::getX86_FP80Ty(b->getContext());
    return ConstantFP::get(bTy, val);
}

static Value *doGEPV(BasicBlock *&b, Value *gepindex, MCSemaRegs reg)
{
    llvm::Type *gepindex_type = gepindex->getType();

    Value *gep_ext = gepindex;

    if (!gepindex_type->isIntegerTy())
      throw TErr(__LINE__, __FILE__, "gepindex number is not an integer");

    if (!gepindex_type->isIntegerTy(32))
    {
        // Zero extend to 32 bits.
        gep_ext = new ZExtInst(gepindex,
            llvm::Type::getInt32Ty(b->getContext()), "", b);
    }

    Value *stGEPV[] = {
        CONST_V<32>(b, 0),
        gep_ext };

    Value* localgepreg = x86::lookupLocal(b->getParent(), reg);

    // Get actual register.
    Instruction *gepreg = GetElementPtrInst::CreateInBounds(localgepreg, stGEPV, "", b);

    return gepreg;
}

static Value *GetFPUTagPtrV(BasicBlock *&b, Value *tagval)
{
    return doGEPV(b, tagval, FPU_TAG);
}

static Value *GetFPUTagV(BasicBlock *&b, Value *tagval)
{
    Value *tagptr = doGEPV(b, tagval, FPU_TAG);
    Value *load = noAliasMCSemaScope(new LoadInst(tagptr, "", b));

    return load;
}

static Value *GetFPURegV(BasicBlock *&b, Value *fpureg)
{
    // Create GEP array to get local value of ST(regslot).
    return doGEPV(b, fpureg, ST0);
}

// Map fpreg (a value from the enum of X86::ST0 - X86::ST7 to register slot in
// the floating point register array. This maps the i in ST(i) to a slot that
// can be used with FPUR_READV/FPUR_WRITEV.
static Value *GetSlotForFPUReg(BasicBlock *&b, unsigned fpreg)
{
    // How far away is this register from ST0?
    // This is needed to find the correct slot in the FPRegs to read from.
    unsigned offset_from_st0 = fpreg - X86::ST0;

    // Sanity check: there are only 8 FPU registers.
    if(offset_from_st0 >= NUM_FPU_REGS)
      throw TErr(__LINE__, __FILE__, "Trying to write to non-existant FPU register");

    Value *topval = F_READ(b, FPU_TOP);
    // Add should overflow automatically.
    Value   *regslot = BinaryOperator::CreateAdd(
                topval,
                CONST_V<3>(b, offset_from_st0),
                "", b);

    NASSERT(regslot != NULL);

    return regslot;
}

static Value* DECREMENT_FPU_TOP(BasicBlock *&b)
{
    // Read TOP.
    Value   *topval = F_READ(b, FPU_TOP);

    Value   *dectop = BinaryOperator::CreateSub(topval, CONST_V<3>(b, 1), "", b);

    // Checking for range removed due to operations on 3-bit integers and
    // automatic overflow.

    F_WRITE(b, FPU_TOP, dectop);

    return dectop;
}

// Increments TOP and returns the new value of TOP.
static Value* INCREMENT_FPU_TOP(BasicBlock *&b)
{
    // Read TOP.
    Value *topval = F_READ(b, FPU_TOP);

    // Increment TOP.
    Value *inctop = BinaryOperator::CreateAdd(topval, CONST_V<3>(b, 1), "", b);

    F_WRITE(b, FPU_TOP, inctop);

    return inctop;
}

// This is the equivalent of return fpuregs[regslot];
// FPU registers are referenced as ST(i) where i [0-7], and references a
// register slot based on the value of the TOP flag.
// So if TOP == 5, then ST(0) references register slot 5, and ST(3) references
// register slot 0.
static Value   *FPUR_READV(BasicBlock *&b, Value *regslot)
{
    // Check TAG register
    // If TAG(regslot) != 0, then we have a problem.
    Value *tagval = GetFPUTagV(b, regslot);
    Function *F = b->getParent();

    BasicBlock *read_normal_block =
        BasicBlock::Create(b->getContext(), "fpu_read_normal", F);
    //BasicBlock *read_zero_block =
    //    BasicBlock::Create(b->getContext(), "fpu_read_zero", F);
    //BasicBlock *read_special_block =
    //    BasicBlock::Create(b->getContext(), "fpu_read_special", F);
    BasicBlock *read_empty_block =
        BasicBlock::Create(b->getContext(), "fpu_read_empty", F);

    BasicBlock *fpu_read_continue =
        BasicBlock::Create(b->getContext(), "fpu_read_continue", F);

    // The default case should never be hit. Use LLVM Switch Node.
    SwitchInst *tagSwitch = SwitchInst::Create(tagval, read_empty_block, 4, b);
    tagSwitch->addCase(CONST_V<2>(b, FPU_TAG_VALID), read_normal_block);
    tagSwitch->addCase(CONST_V<2>(b, FPU_TAG_ZERO), read_normal_block);
    tagSwitch->addCase(CONST_V<2>(b, FPU_TAG_SPECIAL), read_normal_block);
    //tagSwitch->addCase(CONST_V<2>(b, 1), read_zero_block);
    //tagSwitch->addCase(CONST_V<2>(b, 2), read_special_block);
    //tagSwitch->addCase(CONST_V<2>(b, 3), read_empty_block);

    Value *streg = GetFPURegV(read_normal_block, regslot);
    Instruction *loadVal = noAliasMCSemaScope(new LoadInst(streg, "", read_normal_block));

    // C1 is set load needs to round up and cleared otherwise.
    FPUF_CLEAR(read_normal_block, FPU_C1);
    BranchInst::Create(fpu_read_continue, read_normal_block);

    // Populate read zero block.
    // This is the zero block. Return zero.
    // But there are two zeros - negative and positive.
    // Check the sign of the number, then return +0 or -0.
    //Value *streg_z = GetFPURegV(read_zero_block, regslot);
    //Value *loadVal_z = new LoadInst(streg_z, "", read_zero_block);
    //Value *neg_zero = ConstantFP::getNegativeZero(Type::getX86_FP80Ty(read_zero_block->getContext()));
    // Is the value we loaded less than or equal to -0.0?
    //Value *fcmp_inst = new FCmpInst(*read_zero_block, FCmpInst::FCMP_OLE, loadVal_z, neg_zero, "");

    // if val <= -0.0, return -0.0. Otherwise, return +0.0.
    //Value *zval = SelectInst::Create(fcmp_inst, neg_zero,
    //    CONSTFP_V(read_zero_block, 0.0), "", read_zero_block);

    //BranchInst::Create(fpu_read_continue, read_zero_block);

    // Populate read special block.
    // TODO: Check if we need special NaN handling.
    //BranchInst::Create(fpu_read_continue, read_special_block);
    //Value *streg_s = GetFPURegV(read_special_block, regslot);
    //Value *loadVal_s = new LoadInst(streg_s, "", read_special_block);
    //BranchInst::Create(fpu_read_continue, read_special_block);

    // Populate read empty block.
    // For now, just branch to fpu_read_continue and clear C1 to indicate stack
    // underflow.
    // TODO: Throw an exception.
    FPUF_CLEAR(read_empty_block, FPU_C1);
    Value *zval = CONSTFP_V(read_empty_block, 0.0);
    BranchInst::Create(fpu_read_continue, read_empty_block);


    // Populate continue block.
    // Use phi instruction to determine value that was loaded.
    PHINode *whichval =
        PHINode::Create(Type::getX86_FP80Ty(F->getContext()),
                        2,
                        "fpu_switch_phinode",
                        fpu_read_continue);

    whichval->addIncoming(loadVal, read_normal_block);
    //whichval->addIncoming(zval, read_zero_block);
    //whichval->addIncoming(loadVal_s, read_special_block);

    // Would not get here, but throw exception?
    whichval->addIncoming(zval, read_empty_block);

    b = fpu_read_continue;

    // Read PC flag and adjust precision based on its value.
    Value *precision_adjusted = adjustFpuPrecision(b, whichval);
    return precision_adjusted;
}

// Read the value of X86::STi as specified by fpreg.
static Value *FPUR_READ(BasicBlock *&b, unsigned fpreg)
{
    Value *regslot = GetSlotForFPUReg(b, fpreg);
    return FPUR_READV(b, regslot);
}

// This is the equivalent of fpu_st_regs[regslot] = val.
// FPU registers are referenced as ST(i) where i [0-7], and references a
// register slot based of the value of the TOP flag.
// So if TOP == 5, ST(0) references register slot 5, and ST(3) references
// register slot 0.
static void FPUR_WRITEV(BasicBlock *&b, Value *regslot, Value *val)
{
    CREATE_BLOCK(fpu_write, b);
    CREATE_BLOCK(fpu_exception, b);

    // Ensure this has been pre-extended to FP80.
    // If this is a common occurrence, maybe.
    // Always extend?
    NASSERT(val->getType()->isX86_FP80Ty());

    // 1) Get flag for FPU Value - is it already set?
    // if so, then we will overflow. Need to throw exception.

    // Get ptr to FPU register.
    Value *streg = GetFPURegV(b, regslot);
    Value *tagReg = GetFPUTagPtrV(b, regslot);
    Instruction *tagVal = noAliasMCSemaScope(new LoadInst(tagReg, "", b));

    // If tag != empty, then throw exception.
    Value *cmp_inst = new ICmpInst(*b, ICmpInst::ICMP_EQ, tagVal, CONST_V<2>(b, FPU_TAG_EMPTY));

    BranchInst::Create(block_fpu_write, block_fpu_exception, cmp_inst, b);

    // Set up block_fpu_exception.
    // TODO: real exception throwing.
    // For now, just set C1 and branch to write anyway.
    FPUF_SET(block_fpu_exception, FPU_C1);
    BranchInst::Create(block_fpu_write, block_fpu_exception);

    // Default block is now block_fpu_write.
    b = block_fpu_write;

    // Write 0 to tagReg.
    FPUF_CLEAR(b, FPU_C1);
    Instruction *storeVal_normal = noAliasMCSemaScope(new StoreInst(
        CONST_V<2>(b, FPU_TAG_VALID), tagReg, b));

    NASSERT(storeVal_normal != NULL);

    // This is used later, but is needed now so things can branch to it.
    CREATE_BLOCK(fpu_write_exit, b);

    BranchInst::Create(block_fpu_write_exit, b);

    // Write 1 to tagReg.
    //CREATE_BLOCK(fpu_write_zero, b);
    //Value *storeVal_zero = noAliasMCSemaScope(new StoreInst(
    //    CONST_V<2>(block_fpu_write_zero, 1), tagReg, block_fpu_write_zero));
    //NASSERT(storeVal_zero != NULL);
    //BranchInst::Create(block_fpu_write_exit, block_fpu_write_zero);

    // Write 2 to tagReg.
    //CREATE_BLOCK(fpu_write_special, b);
    //Value *storeVal_special = noAliasMCSemaScope(new StoreInst(CONST_V<2>(
    //    block_fpu_write_special, 2), tagReg, block_fpu_write_special));
    //NASSERT(storeVal_special != NULL);

    //BranchInst::Create(block_fpu_write_exit, block_fpu_write_special);

    //CREATE_BLOCK(fpu_write_2, b);
    //CREATE_BLOCK(fpu_write_3, b);

    // Is special value?
    //Value *is_special = new FCmpInst(*b, FCmpInst::FCMP_UNO, val, val, "" );
    //BranchInst::Create(block_fpu_write_special, block_fpu_write_2, is_special, b);

    // Is negative zero value?
    //b = block_fpu_write_2;
    //Value *neg_zero =
    //    ConstantFP::getNegativeZero(Type::getX86_FP80Ty(b->getContext()));
    //Value *is_negzero = new FCmpInst(*b, FCmpInst::FCMP_OEQ, neg_zero, val, "" );
    //BranchInst::Create(block_fpu_write_zero, block_fpu_write_3, is_negzero, b);

    // Is positive zero value?
    //b = block_fpu_write_3;
    //Value *pos_zero = CONSTFP_V(b, 0.0);
    //Value *is_poszero = new FCmpInst(*b, FCmpInst::FCMP_OEQ, pos_zero, val, "" );
    //BranchInst::Create(
    //    block_fpu_write_zero, block_fpu_write_normal, is_poszero, b);

    b = block_fpu_write_exit;
    Value *precision_adjusted = adjustFpuPrecision(b, val);
    // Store value into local ST register array.
    Instruction   *storeVal = noAliasMCSemaScope(new StoreInst(precision_adjusted, streg, b));

    NASSERT(storeVal != NULL);
}

// Write val to X86::STi (specified by fpreg).
static void FPUR_WRITE(BasicBlock *&b, unsigned fpreg, Value *val)
{
    // Map fpreg to register slot in the register array.
    Value *regslot = GetSlotForFPUReg(b, fpreg);
    FPUR_WRITEV(b, regslot, val);
}

// Decrement Top, set ST(TOP) = fpuval.
static void FPU_PUSHV(BasicBlock *&b, Value *fpuval)
{
    Value   *new_top = DECREMENT_FPU_TOP(b);
    Value   *ext_top = new ZExtInst(new_top, Type::getInt32Ty(b->getContext()), "", b);

    // The FPUR_WRITEV will mark the currentTOP as valid in the tag registers.
    FPUR_WRITEV(b, ext_top, fpuval);
}

static void FPU_POP(BasicBlock *&b)
{
    // Set tag at current top as empty.
    Value *topslot = GetSlotForFPUReg(b, X86::ST0);
    Value *tagReg = GetFPUTagPtrV(b, topslot);
    // Should an exception be thrown if an empty FPU value is popped without
    // being used?
    Value *empty_the_tag = noAliasMCSemaScope(new StoreInst(
        CONST_V<2>(b, FPU_TAG_EMPTY), tagReg, b));

    NASSERT(empty_the_tag != NULL);

    INCREMENT_FPU_TOP(b);
}

static Value *FPUM_READ(InstPtr ip, int memwidth, llvm::BasicBlock *&b, Value *addr)
{
    Value *readLoc = addr;
    llvm::Type *ptrTy;
    unsigned addrspace = ip->get_addr_space();

    switch (memwidth)
    {
        case 16:
            throw TErr(__LINE__, __FILE__, "HALFPTR TYPE NOT YET SUPPORTED!");
            break;
        case 32:
            ptrTy = llvm::Type::getFloatPtrTy(b->getContext(), addrspace);
            break;
        case 64:
            ptrTy = llvm::Type::getDoublePtrTy(b->getContext(), addrspace);
            break;
        case 80:
            ptrTy = llvm::Type::getX86_FP80PtrTy(b->getContext(), addrspace);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "FPU TYPE NOT IMPLEMENTED!");
            break;
    }

    readLoc = ADDR_TO_POINTER_V(b, addr, ptrTy);

    Value *read = noAliasMCSemaScope(new llvm::LoadInst(readLoc, "", b));

    // Convert precision - this is here for cases like FPU compares where the
    // compare would fail unless both precisions were adjusted.
    Value *extended;

    if (memwidth < 80)
    {
        extended = new FPExtInst(read,
            llvm::Type::getX86_FP80Ty(b->getContext()), "", b);
    }
    else if (memwidth == 80)
    {
        extended = read;
    }
    else
    {
        throw TErr(__LINE__, __FILE__, "Unsupported FPU type!");
    }

    // Precision adjust works on 80-bit FPU.
    Value *precision_adjusted = adjustFpuPrecision(b, extended);

    // Re-truncate back to requested size.
    Value *returnval;

    switch (memwidth)
    {
        case 32:
            returnval = new FPTruncInst(precision_adjusted,
                llvm::Type::getFloatTy(b->getContext()), "", b);
            break;
        case 64:
            returnval = new FPTruncInst(
                precision_adjusted, llvm::Type::getDoubleTy(b->getContext()),
                "", b);
            break;
        case 80:
            // Do nothing.
            returnval = precision_adjusted;
            break;
        default:
            throw TErr(__LINE__, __FILE__, "FPU TYPE NOT IMPLEMENTED!");
            break;
    }

    return returnval;
}

// Create a new basic block and jump to it from the previous block.
// This is used to set the last FPU instruction pointer via BlockAddr later.
static BasicBlock *createNewFpuBlock(Function *F, BasicBlock *&b, std::string instname)
{
    BasicBlock* newb = BasicBlock::Create(
        F->getContext(), ("fpuinst_" + instname), F);

    Value *br = BranchInst::Create(newb, b);

    NASSERT(br != NULL);

    return newb;
}

static BasicBlock * createNewFpuBlock(BasicBlock *&b, std::string instName)
{
    return createNewFpuBlock(b->getParent(), b, instName);
}

#define SET_STRUCT_MEMBER(st, index, member, b) do {\
    Value *stGEPV[] = {\
        CONST_V<32>(b, 0),\
        CONST_V<32>(b, index) };\
    Instruction *gepreg = GetElementPtrInst::CreateInBounds(st, stGEPV, "", b);\
    Value *storeIt = noAliasMCSemaScope(new StoreInst(member, gepreg, b));\
    NASSERT(storeIt != NULL);\
    } while(0);

template<int width, bool reverse>
static InstTransResult doFiOpMR(InstPtr ip, BasicBlock *&b,
        unsigned dstReg, Value *memAddr,
        unsigned opcode, llvm::Instruction::BinaryOps fpop)
{
    // Read register.
    Value *dstVal = FPUR_READ(b, dstReg);

    // Read memory value.
    Value *memVal = M_READ<width>(ip, b, memAddr);

    Value *fp_mem_val = llvm::CastInst::Create(
            llvm::Instruction::SIToFP,
            memVal,
            llvm::Type::getX86_FP80Ty(b->getContext()),
            "",
            b);

    Value *result;
    if(reverse == false) {
        result = BinaryOperator::Create(fpop, dstVal, fp_mem_val, "", b);
    } else {
        result = BinaryOperator::Create(fpop, fp_mem_val, dstVal, "", b);
    }

    // Store result in dstReg.
    FPUR_WRITE(b, dstReg, result);

    // Next instruction.
    return ContinueBlock;

}

template<int width, bool reverse>
static InstTransResult doFOpMR(InstPtr ip, BasicBlock *&b, unsigned dstReg,
        Value *memAddr, unsigned opcode,
        llvm::Instruction::BinaryOps fpop)
{
    // Read register.
    Value *dstVal = FPUR_READ(b, dstReg);

    // Read memory value.
    Value *memVal = FPUM_READ(ip, width, b, memAddr);

    // Extend memory value to be native FPU type.
    Value *extVal = new FPExtInst(
        memVal, llvm::Type::getX86_FP80Ty(b->getContext()), "", b);

    Value *result;
    if(reverse == false) {
        result = BinaryOperator::Create(fpop, dstVal, extVal, "", b);
    } else {
        result = BinaryOperator::Create(fpop, extVal, dstVal, "", b);
    }

    // Store result in dstReg.
    FPUR_WRITE(b, dstReg, result);

    // Next instruction.
    return ContinueBlock;
}

template <bool reverse>
static InstTransResult doFOpRR(InstPtr ip, BasicBlock *&b,
        unsigned srcReg, unsigned dstReg, unsigned opcode,
        llvm::Instruction::BinaryOps fpop)
{
    // Load source.
    Value *srcVal = FPUR_READ(b, srcReg);

    // Load destination.
    Value *dstVal = FPUR_READ(b, dstReg);

    Value *result;
    if (reverse == false) {
        result = BinaryOperator::Create(fpop, srcVal, dstVal, "", b);
    } else {
        result = BinaryOperator::Create(fpop, dstVal, srcVal, "", b);
    }

    // Store result in dstReg.
    FPUR_WRITE(b, dstReg, result);

    // Set if result is rounded up, clear otherwise.
    FPUF_CLEAR(b, FPU_C1);

    // Next instruction.
    return ContinueBlock;
}

template <bool reverse>
static InstTransResult doFOpPRR(InstPtr ip, BasicBlock *&b,
    unsigned srcReg, unsigned dstReg, unsigned opcode,
        llvm::Instruction::BinaryOps fpop)
{
    // Do the operation.
    doFOpRR<reverse>(ip, b, srcReg, dstReg, opcode, fpop);

    // Pop the stack.
    FPU_POP(b);

    // Next instruction.
    return ContinueBlock;
}

static InstTransResult doFldcw(InstPtr ip, BasicBlock *&b, Value *memAddr)
{
    Value *memPtr = ADDR_TO_POINTER<16>(b, memAddr);

    Value *memVal = M_READ<16>(ip, b, memPtr);

    SHR_SET_FLAG<16, 1>(b, memVal, FPU_IM, 0 );
    SHR_SET_FLAG<16, 1>(b, memVal, FPU_DM, 1 );
    SHR_SET_FLAG<16, 1>(b, memVal, FPU_ZM, 2 );
    SHR_SET_FLAG<16, 1>(b, memVal, FPU_OM, 3 );
    SHR_SET_FLAG<16, 1>(b, memVal, FPU_UM, 4 );
    SHR_SET_FLAG<16, 1>(b, memVal, FPU_PM, 5 );
    SHR_SET_FLAG<16, 2>(b, memVal, FPU_PC, 8 );
    SHR_SET_FLAG<16, 2>(b, memVal, FPU_RC, 10);
    SHR_SET_FLAG<16, 1>(b, memVal, FPU_X,  12);

    return ContinueBlock;
}

static InstTransResult doFstcw(InstPtr ip, BasicBlock *&b, Value *memAddr)
{
    Value *memPtr = ADDR_TO_POINTER<16>(b, memAddr);

    // Pre-clear reserved FPU bits.
    Value *cw = CONST_V<16>(b, 0x1F7F);

    cw = SHL_NOTXOR_FLAG<16>(b, cw, FPU_IM, 0);
    cw = SHL_NOTXOR_FLAG<16>(b, cw, FPU_DM, 1);
    cw = SHL_NOTXOR_FLAG<16>(b, cw, FPU_ZM, 2);
    cw = SHL_NOTXOR_FLAG<16>(b, cw, FPU_OM, 3);
    cw = SHL_NOTXOR_FLAG<16>(b, cw, FPU_UM, 4);
    cw = SHL_NOTXOR_FLAG<16>(b, cw, FPU_PM, 5);
    cw = SHL_NOTXOR_FLAG<16>(b, cw, FPU_PC, 8);
    cw = SHL_NOTXOR_FLAG<16>(b, cw, FPU_RC, 10);
    cw = SHL_NOTXOR_FLAG<16>(b, cw, FPU_X, 12);

    Value *store = noAliasMCSemaScope(new StoreInst(cw, memPtr, b));

    return ContinueBlock;
}

static InstTransResult doFstenv(InstPtr ip, BasicBlock *&b, Value *memAddr)
{
    llvm::Module *M = b->getParent()->getParent();
    unsigned int bitWidth = getPointerSize(M);

    Value *memPtr = ADDR_TO_POINTER<8>(b, memAddr);

    // Pre-clear reserved FPU bits.
    Value *cw = CONST_V<32>(b, 0xFFFF1F7F);

    cw = SHL_NOTXOR_FLAG<32>(b, cw, FPU_IM, 0);
    cw = SHL_NOTXOR_FLAG<32>(b, cw, FPU_DM, 1);
    cw = SHL_NOTXOR_FLAG<32>(b, cw, FPU_ZM, 2);
    cw = SHL_NOTXOR_FLAG<32>(b, cw, FPU_OM, 3);
    cw = SHL_NOTXOR_FLAG<32>(b, cw, FPU_UM, 4);
    cw = SHL_NOTXOR_FLAG<32>(b, cw, FPU_PM, 5);
    cw = SHL_NOTXOR_FLAG<32>(b, cw, FPU_PC, 8);
    cw = SHL_NOTXOR_FLAG<32>(b, cw, FPU_RC, 10);
    cw = SHL_NOTXOR_FLAG<32>(b, cw, FPU_X, 12);

    Value *sw = CONST_V<32>(b, 0xFFFFFFFF);

    sw = SHL_NOTXOR_FLAG<32>(b, sw, FPU_IE, 0);
    sw = SHL_NOTXOR_FLAG<32>(b, sw, FPU_DE, 1);
    sw = SHL_NOTXOR_FLAG<32>(b, sw, FPU_ZE, 2);
    sw = SHL_NOTXOR_FLAG<32>(b, sw, FPU_OE, 3);
    sw = SHL_NOTXOR_FLAG<32>(b, sw, FPU_UE, 4);
    sw = SHL_NOTXOR_FLAG<32>(b, sw, FPU_PE, 5);
    sw = SHL_NOTXOR_FLAG<32>(b, sw, FPU_SF, 6);
    sw = SHL_NOTXOR_FLAG<32>(b, sw, FPU_ES, 7);
    sw = SHL_NOTXOR_FLAG<32>(b, sw, FPU_C0, 8);
    sw = SHL_NOTXOR_FLAG<32>(b, sw, FPU_C1, 9);
    sw = SHL_NOTXOR_FLAG<32>(b, sw, FPU_C2, 10);
    sw = SHL_NOTXOR_FLAG<32>(b, sw, FPU_TOP, 11);
    sw = SHL_NOTXOR_FLAG<32>(b, sw, FPU_C3, 14);
    sw = SHL_NOTXOR_FLAG<32>(b, sw, FPU_B, 15);

    Value *tw = CONST_V<32>(b, 0xFFFFFFFF);

    tw = SHL_NOTXOR_V<32>(b, tw, GetFPUTagV(b, CONST_V<32>(b, 0)), 0);
    tw = SHL_NOTXOR_V<32>(b, tw, GetFPUTagV(b, CONST_V<32>(b, 1)), 2);
    tw = SHL_NOTXOR_V<32>(b, tw, GetFPUTagV(b, CONST_V<32>(b, 2)), 4);
    tw = SHL_NOTXOR_V<32>(b, tw, GetFPUTagV(b, CONST_V<32>(b, 3)), 6);
    tw = SHL_NOTXOR_V<32>(b, tw, GetFPUTagV(b, CONST_V<32>(b, 4)), 8);
    tw = SHL_NOTXOR_V<32>(b, tw, GetFPUTagV(b, CONST_V<32>(b, 5)), 10);
    tw = SHL_NOTXOR_V<32>(b, tw, GetFPUTagV(b, CONST_V<32>(b, 6)), 12);
    tw = SHL_NOTXOR_V<32>(b, tw, GetFPUTagV(b, CONST_V<32>(b, 7)), 14);

    Value *fpu_ip = F_READ(b, FPU_LASTIP_OFF);
    Value *fpu_seg_op = CONST_V<32>(b, 0x0);
    fpu_seg_op = SHL_NOTXOR_V<32>(b, fpu_seg_op, F_READ(b, FPU_LASTIP_SEG), 0);
    fpu_seg_op = SHL_NOTXOR_V<32>(b, fpu_seg_op, F_READ(b, FPU_FOPCODE), 16);

    Value *fpu_dp_o = F_READ(b, FPU_LASTDATA_OFF);
    Value *fpu_dp_s = CONST_V<32>(b, 0xFFFFFFFF);
    fpu_dp_s = SHL_NOTXOR_V<32>(b, fpu_dp_s, F_READ(b, FPU_LASTDATA_SEG), 0);
    StructType *fpuenv_t = StructType::create(b->getContext(), "struct.fpuenv");
    std::vector<Type *>  envfields;
    envfields.push_back(Type::getInt32Ty(b->getContext()));
    envfields.push_back(Type::getInt32Ty(b->getContext()));
    envfields.push_back(Type::getInt32Ty(b->getContext()));
    envfields.push_back(Type::getIntNTy(b->getContext(), bitWidth));
    envfields.push_back(Type::getInt32Ty(b->getContext()));
    envfields.push_back(Type::getIntNTy(b->getContext(), bitWidth));
    envfields.push_back(Type::getInt32Ty(b->getContext()));

    fpuenv_t->setBody(envfields, true);
    //make a pointer type for struct.fpuenv
    PointerType *ptype = PointerType::get(fpuenv_t, 0);
    //cast memPtr to a pointer to struct.fpuenv *
    Value *k = new BitCastInst(memPtr, ptype, "", b);
    //perform field writes
    SET_STRUCT_MEMBER(k, 0, cw, b);
    SET_STRUCT_MEMBER(k, 1, sw, b);
    SET_STRUCT_MEMBER(k, 2, tw, b);
    SET_STRUCT_MEMBER(k, 3, fpu_ip, b);
    SET_STRUCT_MEMBER(k, 4, fpu_seg_op, b);
    SET_STRUCT_MEMBER(k, 5, fpu_dp_o, b);
    SET_STRUCT_MEMBER(k, 6, fpu_dp_s, b);

    return ContinueBlock;
}

template <int width>
static InstTransResult doFildM(InstPtr ip, BasicBlock *&b, Value *memAddr)
{
    NASSERT(memAddr != NULL);

    // Read memory value.
    Value *memVal = M_READ<width>(ip, b, memAddr);

    Value *fp_mem_val = llvm::CastInst::Create(
            llvm::Instruction::SIToFP,
            memVal,
            llvm::Type::getX86_FP80Ty(b->getContext()),
            "",
            b);

    // Step 3: Adjust FPU stack: TOP = TOP - 1
    // Step 4: ST(0) = fpuVal
    FPU_PUSHV(b, fp_mem_val);

    // Next instruction.
    return ContinueBlock;
}

template <int width>
static InstTransResult doFldM(InstPtr ip, BasicBlock *&b, Value *memAddr)
{
    NASSERT(memAddr != NULL);

    // Step 1: read value from memory.
    Value *memVal = FPUM_READ(ip, width, b, memAddr);

    // Step 2: Convert value to x87 double precision FP.
    llvm::Type *fpuType = llvm::Type::getX86_FP80Ty(b->getContext());
    Value *fpuVal;

    if (!memVal->getType()->isX86_FP80Ty())
    {
        fpuVal = new FPExtInst(memVal, fpuType, "", b);
    }
    else
    {
        fpuVal = memVal;
    }

    // Step 3: Adjust FPU stack: TOP = TOP - 1
    // Step 4: ST(0) = fpuVal

    FPU_PUSHV(b, fpuVal);

    // Step 5: set flags.

    // Next instruction.
    return ContinueBlock;
}

static InstTransResult doFldC(InstPtr ip, BasicBlock *&b, double constv) {

    // load constant onto FPU stack
    Value *fp_const = CONSTFP_V(b, constv);
    FPU_PUSHV(b, fp_const);
    return ContinueBlock;

}

static InstTransResult doFldR(InstPtr ip, BasicBlock *&b, const MCOperand &r)
{
    // Make sure that this is a register.
    NASSERT(r.isReg());

    // Read register.
    Value *srcVal = FPUR_READ(b, r.getReg());

    // Push value on stack.
    FPU_PUSHV(b, srcVal);

    // Next instruction.
    return ContinueBlock;
}

template<int width>
static InstTransResult doFistM(InstPtr ip, BasicBlock *&b, Value *memAddr)
{
    NASSERT(memAddr != NULL);

    Value *regVal = FPUR_READ(b, X86::ST0);

    Value *ToInt = llvm::CastInst::Create(
            llvm::Instruction::FPToSI,
            regVal,
            Type::getIntNTy(b->getContext(), width),
            "",
            b);

    M_WRITE<width>(ip, b, memAddr, ToInt);

    // Next instruction.
    return ContinueBlock;
}

template<int width>
static InstTransResult doFstM(InstPtr ip, BasicBlock *&b, Value *memAddr)
{
    NASSERT(memAddr != NULL);

    Value *regVal = FPUR_READ(b, X86::ST0);
    llvm::Type *destType;
    llvm::Type *ptrType;
    unsigned addrspace = ip->get_addr_space();

    switch (width)
    {
        case 32:
            destType = llvm::Type::getFloatTy(b->getContext());
            ptrType = llvm::Type::getFloatPtrTy(b->getContext(), addrspace);
            break;
        case 64:
            destType = llvm::Type::getDoubleTy(b->getContext());
            ptrType = llvm::Type::getDoublePtrTy(b->getContext(), addrspace);
            break;
        case 80:
            //destType = llvm::Type::getX86_FP80Ty(b->getContext());
            ptrType = llvm::Type::getX86_FP80PtrTy(b->getContext(), addrspace);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Invalid width specified for FST");
            break;
    }

    // do not truncate 80-bit to 80-bit, causes a truncation error
    if(width < 80)
    {
        Value *trunc = new FPTruncInst(regVal, destType, "", b);
        M_WRITE_T(ip, b, memAddr, trunc, ptrType);
    }
    else if(width == 80)
    {
        M_WRITE_T(ip, b, memAddr, regVal, ptrType);
    }
    else
    {
        throw TErr(__LINE__, __FILE__, "FPU Registers >80 bits not implemented for FST");
    }

    // Next instruction.
    return ContinueBlock;
}

template<int width>
static InstTransResult doFstpM(InstPtr ip, BasicBlock *&b, Value *memAddr)
{
    // Do the FST.
    doFstM<width>(ip, b, memAddr);

    // Pop the stack.
    FPU_POP(b);

    // Next instruction.
    return ContinueBlock;
}

// TODO: This is like FISTP, but FISTTP does not check rounding mode and
// always rounds to zero. 
template<int width>
static InstTransResult doFistTpM(InstPtr ip, BasicBlock *&b, Value *memAddr)
{
    // Do the FST.
    doFistM<width>(ip, b, memAddr);

    // Pop the stack.
    FPU_POP(b);

    // Next instruction.
    return ContinueBlock;
}

template<int width>
static InstTransResult doFistpM(InstPtr ip, BasicBlock *&b, Value *memAddr)
{
    // Do the FST.
    doFistM<width>(ip, b, memAddr);

    // Pop the stack.
    FPU_POP(b);

    // Next instruction.
    return ContinueBlock;
}

static InstTransResult doFstR(InstPtr ip, BasicBlock *&b, const MCOperand &r)
{
    // Make sure that this is a register.
    NASSERT(r.isReg());

    // Read ST0.
    Value *srcVal = FPUR_READ(b, X86::ST0);

    // Write register.
    FPUR_WRITE(b, r.getReg(), srcVal);

    // Next instruction.
    return ContinueBlock;
}

static InstTransResult doFstpR(InstPtr ip, BasicBlock *&b, const MCOperand &r)
{
    // Do the FST.
    doFstR(ip, b, r);

    // Pop the stack.
    FPU_POP(b);

    // Next instruction.
    return ContinueBlock;
}

static InstTransResult doFsin(InstPtr ip, BasicBlock *&b, unsigned reg)
{
    Module *M = b->getParent()->getParent();

    Value *regval = FPUR_READ(b, reg);

    // get a declaration for llvm.fsin
    Type *t = llvm::Type::getX86_FP80Ty(b->getContext());
    Function *fsin_func = Intrinsic::getDeclaration(M, Intrinsic::sin, t);

    NASSERT(fsin_func != NULL);

    // call llvm.fsin(reg)
    std::vector<Value*> args;
    args.push_back(regval);

    Value *fsin_val = CallInst::Create(fsin_func, args, "", b);

    // store return in reg
    FPUR_WRITE(b, reg, fsin_val);

    return ContinueBlock;
}

static InstTransResult doFucom(
        InstPtr ip,
        BasicBlock *&b,
        unsigned reg,
        unsigned int stackPops)
{
    Value *st0_val = FPUR_READ(b, X86::ST0);
    Value *sti_val = FPUR_READ(b, reg);

    // TODO: Make sure these treat negative zero and positive zero
    // as the same value.
    Value *is_lt = new FCmpInst(*b, FCmpInst::FCMP_ULT, st0_val, sti_val);
    Value *is_eq = new FCmpInst(*b, FCmpInst::FCMP_UEQ, st0_val, sti_val);

    // if BOTH the equql AND less than is true
    // it means that one of the ops is a QNaN

    Value *lt_and_eq = BinaryOperator::CreateAnd(is_lt, is_eq, "", b);

    F_WRITE(b, FPU_C0, is_lt);        // C0 is 1 if either is QNaN or op1 < op2
    F_WRITE(b, FPU_C3, is_eq);        // C3 is 1 if either is QNaN or op1 == op2
    F_WRITE(b, FPU_C2, lt_and_eq);    // C2 is 1 if either op is a QNaN

    while(stackPops > 0) {
        FPU_POP(b);
        stackPops -= 1;
    }

    return ContinueBlock;
}

static InstTransResult doFucomi(
        InstPtr ip, 
        BasicBlock *&b, 
        unsigned reg,
        unsigned int stackPops)
{
    Value *st0_val = FPUR_READ(b, X86::ST0);
    Value *sti_val = FPUR_READ(b, reg);

    // TODO: Make sure these treat negative zero and positive zero
    // as the same value.
    Value *is_lt = new FCmpInst(*b, FCmpInst::FCMP_ULT, st0_val, sti_val);
    Value *is_eq = new FCmpInst(*b, FCmpInst::FCMP_UEQ, st0_val, sti_val);

    // if BOTH the equql AND less than is true
    // it means that one of the ops is a QNaN
    
    Value *lt_and_eq = BinaryOperator::CreateAnd(is_lt, is_eq, "", b);

    F_WRITE(b, CF, is_lt);        // C0 is 1 if either is QNaN or op1 < op2
    F_WRITE(b, ZF, is_eq);        // C3 is 1 if either is QNaN or op1 == op2
    F_WRITE(b, PF, lt_and_eq);    // C2 is 1 if either op is a QNaN

    while(stackPops > 0) {
        FPU_POP(b);
        stackPops -= 1;
    }

    return ContinueBlock;
}

static Value* doFstsV(BasicBlock *&b)
{

    Value *sw = CONST_V<16>(b, 0xFFFF);

    sw = SHL_NOTXOR_FLAG<16>(b, sw, FPU_IE,  0);
    sw = SHL_NOTXOR_FLAG<16>(b, sw, FPU_DE,  1);
    sw = SHL_NOTXOR_FLAG<16>(b, sw, FPU_ZE,  2);
    sw = SHL_NOTXOR_FLAG<16>(b, sw, FPU_OE,  3);
    sw = SHL_NOTXOR_FLAG<16>(b, sw, FPU_UE,  4);
    sw = SHL_NOTXOR_FLAG<16>(b, sw, FPU_PE,  5);
    sw = SHL_NOTXOR_FLAG<16>(b, sw, FPU_SF,  6);
    sw = SHL_NOTXOR_FLAG<16>(b, sw, FPU_ES,  7);
    sw = SHL_NOTXOR_FLAG<16>(b, sw, FPU_C0,  8);
    sw = SHL_NOTXOR_FLAG<16>(b, sw, FPU_C1,  9);
    sw = SHL_NOTXOR_FLAG<16>(b, sw, FPU_C2, 10);
    sw = SHL_NOTXOR_FLAG<16>(b, sw, FPU_TOP,11);
    sw = SHL_NOTXOR_FLAG<16>(b, sw, FPU_C3, 14);
    sw = SHL_NOTXOR_FLAG<16>(b, sw, FPU_B,  15);

    return sw;
}

static InstTransResult doFstswm(InstPtr ip, BasicBlock *&b, Value *memAddr)
{
    Value *memPtr = ADDR_TO_POINTER<16>(b, memAddr);

    Value *status_word = doFstsV(b);

    M_WRITE<16>(ip, b, memPtr, status_word);

    return ContinueBlock;
}

static InstTransResult doFstswr(InstPtr ip, BasicBlock *&b)
{
    Value *status_word = doFstsV(b);

    R_WRITE<16>(b, X86::AX, status_word);

    return ContinueBlock;
}

static InstTransResult doFxch(MCInst &inst, InstPtr ip, BasicBlock *&b)
{
    // Check num operands.
    // No operands implies ST1
    unsigned src_reg = X86::ST1;
    if(inst.getNumOperands() > 0) {
        src_reg = inst.getOperand(0).getReg();
    }

    Value *src_val = FPUR_READ(b, src_reg);
    Value *st0_val = FPUR_READ(b, X86::ST0);

    FPUR_WRITE(b, X86::ST0, src_val);
    FPUR_WRITE(b, src_reg, st0_val);

    return ContinueBlock;
}

static InstTransResult doF2XM1(MCInst &inst, InstPtr ip, BasicBlock *&b)
{

	/*
     * Computes (2**st0)-1 and stores in ST0
	 */

	Value *st0_val = FPUR_READ(b, X86::ST0);

	Module *M = b->getParent()->getParent();

	Type *t = llvm::Type::getX86_FP80Ty(b->getContext());
	Function *exp_func = Intrinsic::getDeclaration(M, Intrinsic::exp2, t);
	NASSERT(exp_func != nullptr);

	std::vector<Value*> args;

    args.push_back(st0_val);

	Value *exp2_val = CallInst::Create(exp_func, args, "", b);

    Value *one = CONSTFP_V(b, 1.0);

    Value *exp2_m_1 = BinaryOperator::Create(llvm::Instruction::FSub, exp2_val, one, "", b);

	// store return in reg
	FPUR_WRITE(b, X86::ST0, exp2_m_1);

	return ContinueBlock;
}

static InstTransResult doFSCALE(MCInst &inst, InstPtr ip, BasicBlock *&b)
{

	/*
     * st0 = st0 * (2 ** RoundToZero(st1))
	 */

	Module *M = b->getParent()->getParent();

	Value *st0_val = FPUR_READ(b, X86::ST0);
	Value *st1_val = FPUR_READ(b, X86::ST0);


	Type *t = llvm::Type::getX86_FP80Ty(b->getContext());

	Function *exp_func = Intrinsic::getDeclaration(M, Intrinsic::exp2, t);

    Function *trunc_func = Intrinsic::getDeclaration(M, Intrinsic::trunc, t);

	NASSERT(exp_func != nullptr);
	NASSERT(trunc_func != nullptr);

    // round st1 to zero
	std::vector<Value*> args;
    args.push_back(st1_val);
	Value *trunc_st1_val = CallInst::Create(trunc_func, args, "", b);

    // calculate 2^st1
    std::vector<Value*> exp_args;
    exp_args.push_back(trunc_st1_val);
	Value *exp2_val = CallInst::Create(exp_func, exp_args, "", b);

    // st0 * 2*st1
    Value *scaled_val = BinaryOperator::Create(
            llvm::Instruction::FMul, st0_val, exp2_val, "", b);

	// store return in reg
	FPUR_WRITE(b, X86::ST0, scaled_val);

	return ContinueBlock;
}


template<bool p>
static InstTransResult doFYL2Xx(MCInst &inst, InstPtr ip, BasicBlock *&b)
{

	/*
	 * Computes (ST(1) ∗ log2(ST(0))), stores the result in ST(1), and pops the x87 register stack. The value
	 * in ST(0) must be greater than zero.
	 * If the zero-divide-exception mask (ZM) bit in the x87 control word is set to 1 and ST(0) contains ±zero, the instruction returns ∞ with the opposite sign of the value in register ST(1).
	 */

	Value *st0_val = FPUR_READ(b, X86::ST0);
	Value *st1_val = FPUR_READ(b, X86::ST1);

	Module *M = b->getParent()->getParent();
	Type *t = llvm::Type::getX86_FP80Ty(b->getContext());
	Function *flog2_func = Intrinsic::getDeclaration(M, Intrinsic::log2, t);

	NASSERT(flog2_func != NULL);

	std::vector<Value*> args;

	if (p) // FYLX2P1 case
	{
		llvm::Constant *one = llvm::ConstantFP::get(llvm::Type::getX86_FP80Ty(b->getContext()), 1.0);

		Value *st0_plus_one = BinaryOperator::Create(llvm::Instruction::FAdd, st0_val, one, "", b);
		args.push_back(st0_plus_one);
	} else {
		args.push_back(st0_val);
	}

	Value *flog2_val = CallInst::Create(flog2_func, args, "", b);

	Value *result = BinaryOperator::Create(llvm::Instruction::FMul, flog2_val, st1_val, "", b);

	// store return in reg
	FPUR_WRITE(b, X86::ST1, result);

	FPU_POP(b);

	return ContinueBlock;
}

static InstTransResult doFRNDINT(MCInst &inst, InstPtr ip, BasicBlock *&b)
{
    Module *M = b->getParent()->getParent();

    Value *regVal = FPUR_READ(b, X86::ST0);
	Type *fpTy = llvm::Type::getX86_FP80Ty(b->getContext());

    // get our intrinsics
    /// nearest
	Function *round_nearest = Intrinsic::getDeclaration(M, Intrinsic::nearbyint, fpTy);
    NASSERT(round_nearest != NULL);
    // round will round away from zero
	Function *round_down = Intrinsic::getDeclaration(M, Intrinsic::round, fpTy);
    NASSERT(round_down != NULL);
    // round will round away from zero
	Function *round_up = Intrinsic::getDeclaration(M, Intrinsic::round, fpTy);
    NASSERT(round_up != NULL);
    // truncate
    //
	Function *round_zero = Intrinsic::getDeclaration(M, Intrinsic::trunc, fpTy);
    NASSERT(round_zero != NULL);

    CREATE_BLOCK(nearest, b);
    CREATE_BLOCK(down, b);
    CREATE_BLOCK(up, b);
    CREATE_BLOCK(zero, b);
    CREATE_BLOCK(finished, b);

    // switch on Rounding control
    Value *rc = F_READ(b, FPU_RC);
    SwitchInst *rcSwitch = SwitchInst::Create(rc, block_nearest, 4, b);
    rcSwitch->addCase(CONST_V<2>(b, 0), block_nearest);
    rcSwitch->addCase(CONST_V<2>(b, 1), block_down);
    rcSwitch->addCase(CONST_V<2>(b, 2), block_up);
    rcSwitch->addCase(CONST_V<2>(b, 3), block_zero);

    std::vector<Value*> args;
    args.push_back(regVal);

	Value *nearest_val = CallInst::Create(round_nearest, args, "", block_nearest);
    BranchInst::Create(block_finished, block_nearest);

	Value *down_val = CallInst::Create(round_down, args, "", block_down);
    BranchInst::Create(block_finished, block_down);

	Value *up_val = CallInst::Create(round_up, args, "", block_up);
    BranchInst::Create(block_finished, block_up);

	Value *zero_val = CallInst::Create(round_zero, args, "", block_zero);
    BranchInst::Create(block_finished, block_zero);

    // adjust to whichever branch we did
    PHINode *roundedVal =
        PHINode::Create(Type::getX86_FP80Ty(block_finished->getContext()),
                        4,
                        "fpu_round",
                        block_finished);

    roundedVal->addIncoming(nearest_val, block_nearest);
    roundedVal->addIncoming(down_val, block_down);
    roundedVal->addIncoming(up_val, block_up);
    roundedVal->addIncoming(zero_val, block_zero);

    b = block_finished;

    // write it back
    FPUR_WRITE(b, X86::ST0, roundedVal);

    return ContinueBlock;
}

static InstTransResult doFABS(MCInst &inst, InstPtr ip, BasicBlock *&b)
{

	Value *st0_val = FPUR_READ(b, X86::ST0);

	Module *M = b->getParent()->getParent();
	Type *t = llvm::Type::getX86_FP80Ty(b->getContext());
	Function *func = Intrinsic::getDeclaration(M, Intrinsic::fabs, t);

	NASSERT(func != NULL);

	std::vector<Value*> args;
	args.push_back(st0_val);

	Value *result = CallInst::Create(func, args, "", b);

	// store return in reg
	FPUR_WRITE(b, X86::ST0, result);


	return ContinueBlock;
}

static InstTransResult doFSQRT(MCInst &inst, InstPtr ip, BasicBlock *&b)
{

	Value *st0_val = FPUR_READ(b, X86::ST0);

	Module *M = b->getParent()->getParent();
	Type *t = llvm::Type::getX86_FP80Ty(b->getContext());
	Function *func = Intrinsic::getDeclaration(M, Intrinsic::sqrt, t);

	NASSERT(func != NULL);

	std::vector<Value*> args;
	args.push_back(st0_val);

	Value *result = CallInst::Create(func, args, "", b);

	// store return in reg
	FPUR_WRITE(b, X86::ST0, result);


	return ContinueBlock;
}

static InstTransResult doFCOS(MCInst &inst, InstPtr ip, BasicBlock *&b)
{

	Value *st0_val = FPUR_READ(b, X86::ST0);

	Module *M = b->getParent()->getParent();
	Type *t = llvm::Type::getX86_FP80Ty(b->getContext());
	Function *func = Intrinsic::getDeclaration(M, Intrinsic::cos, t);

	NASSERT(func != NULL);

	std::vector<Value*> args;
	args.push_back(st0_val);

	Value *result = CallInst::Create(func, args, "", b);

	// store return in reg
	FPUR_WRITE(b, X86::ST0, result);

	/* XXX: If the radian value lies outside the valid range of –263
	 *  to +263 radians, the instruction sets the C2 flag in the x87
	 *  status word to 1 to indicate the value is out of range and
	 *  does not change the value in ST(0).
	 */


	return ContinueBlock;
}
static InstTransResult doFSINCOS(MCInst &inst, InstPtr ip, BasicBlock *&b)
{

	/*
	 * Computes the sine and cosine of the value in ST(0), stores the sine in ST(0),
	 *   and pushes the cosine onto the x87 register stack. The source value must be
	 *   in the range –263 to +263 radians.
	 */

	Value *st0_val = FPUR_READ(b, X86::ST0);

	Module *M = b->getParent()->getParent();
	Type *t = llvm::Type::getX86_FP80Ty(b->getContext());

	Function *sin = Intrinsic::getDeclaration(M, Intrinsic::sin, t);
	Function *cos = Intrinsic::getDeclaration(M, Intrinsic::cos, t);

	NASSERT(sin != NULL);
	NASSERT(cos != NULL);

	// Compute the sin of st(0)
	std::vector<Value*> args;
	args.push_back(st0_val);
	Value *sin_result = CallInst::Create(sin, args, "", b);

	// store the result of the sin call back into st(0)
	FPUR_WRITE(b, X86::ST0, sin_result);

	// Compute the cos of st(0)
	args.clear();
	args.push_back(st0_val);
	Value *cos_result = CallInst::Create(cos, args, "", b);

	// Push the result of the cos on the register stack
	FPU_PUSHV(b, cos_result);

	return ContinueBlock;
}

static InstTransResult doFINCSTP(MCInst &inst, InstPtr ip, BasicBlock *&b)
{

	INCREMENT_FPU_TOP(b);

	return ContinueBlock;
}

static InstTransResult doFDECSTP(MCInst &inst, InstPtr ip, BasicBlock *&b)
{

	DECREMENT_FPU_TOP(b);

	return ContinueBlock;
}

static InstTransResult doFPTAN(MCInst &inst, InstPtr ip, BasicBlock *&b)
{
	Module *M = b->getParent()->getParent();
    Type *t = llvm::Type::getX86_FP80Ty(b->getContext());
	Function *sin = Intrinsic::getDeclaration(M, Intrinsic::sin, t);
	Function *cos = Intrinsic::getDeclaration(M, Intrinsic::cos, t);

	NASSERT(sin != NULL);
	NASSERT(cos != NULL);

	Value *st0_val = FPUR_READ(b, X86::ST0);

	// Compute the sin of st(0)
	std::vector<Value*> args;
	args.push_back(st0_val);
	Value *sin_result = CallInst::Create(sin, args, "", b);

	// Compute the cos of st(0)
	args.clear();
	args.push_back(st0_val);
	Value *cos_result = CallInst::Create(cos, args, "", b);

    // tan = sin/cos
    
    Value *tan_result = BinaryOperator::Create(llvm::Instruction::FDiv, sin_result, cos_result, "", b);

	FPUR_WRITE(b, X86::ST0, tan_result);
    Value *one = CONSTFP_V(b, 1.0);
    FPU_PUSHV(b, one);
    return ContinueBlock;
}

static InstTransResult doCHS(MCInst &inst, InstPtr ip, BasicBlock *&b)
{
	Value *st0_val = FPUR_READ(b, X86::ST0);

    Value *negone = CONSTFP_V(b, -1.0);
    Value *signchange = BinaryOperator::Create(llvm::Instruction::FMul, st0_val, negone, "", b);

	FPUR_WRITE(b, X86::ST0, signchange);
    return ContinueBlock;
}

            //mem_src =  IMM_AS_DATA_REF(block, natM, ip);\

#define FPU_TRANSLATION(NAME, SETPTR, SETDATA, SETFOPCODE, ACCESSMEM, THECALL) static InstTransResult translate_ ## NAME (NativeModulePtr natM, BasicBlock *&block, InstPtr ip, MCInst &inst)\
{\
    InstTransResult ret;\
    block = createNewFpuBlock(block, #NAME);\
    Function *F = block->getParent();\
    Value *mem_src = NULL;\
    if (ACCESSMEM) {\
        if( ip->has_mem_reference ) {\
            mem_src =  MEM_REFERENCE(0);\
            if (SETDATA) { setFpuDataPtr(block, mem_src); }\
        } else {\
            mem_src = ADDR_NOREF(0);\
            if (SETDATA) { setFpuDataPtr(block, mem_src); }\
        }\
    }\
    if (SETPTR) { setFpuInstPtr(block); }\
    ret = THECALL;\
    if (SETFOPCODE) { SET_FPU_FOPCODE(block, inst.native_opcode); }\
    return ret;\
}

/***************************
 ***************************

 WARNING WARNING WARNING

 ***************************
 ***************************

 Many of these templated functions take an argument
 named "reverse". This will reverse the order of operands
 in the instruction. It is used to have a common implementation
 for things like SUB and SUBR.

 *** for *DIV* instructions, reverse is the OPPOSITE of normal, since *DIV*
 instructions have an operand order opposite of other instructions ***
 ** EXCEPT for those that use memory operands. Since there is no write to memory,
 the order stays the same. Yes, this is confusing.**


 ***************************
 ***************************
*/

FPU_TRANSLATION(ADD_F32m, true, true, true, true,
    (doFOpMR<32,false>(ip, block, X86::ST0, mem_src, X86::ADD_F32m, llvm::Instruction::FAdd)) )
FPU_TRANSLATION(ADD_F64m, true, true, true, true,
    (doFOpMR<64,false>(ip, block, X86::ST0, mem_src, X86::ADD_F64m, llvm::Instruction::FAdd)) )
FPU_TRANSLATION(ADD_FI16m, true, true, true, true,
    (doFiOpMR<16, false>(ip, block, X86::ST0, mem_src, X86::ADD_FI16m, llvm::Instruction::FAdd) )
    )
FPU_TRANSLATION(ADD_FI32m, true, true, true, true,
    (doFiOpMR<32, false>(ip, block, X86::ST0, mem_src, X86::ADD_FI32m, llvm::Instruction::FAdd))
    )
FPU_TRANSLATION(ADD_FPrST0, true, false, true, false,
    doFOpPRR<false>(ip, block, X86::ST0, OP(0).getReg(), X86::ADD_FPrST0, llvm::Instruction::FAdd))
FPU_TRANSLATION(ADD_FST0r, true, false, true, false,
    doFOpRR<false>(ip, block, OP(0).getReg(), X86::ST0, X86::ADD_FST0r, llvm::Instruction::FAdd))
FPU_TRANSLATION(ADD_FrST0, true, false, true, false,
    doFOpRR<false>(ip, block, X86::ST0, OP(0).getReg(), X86::ADD_FrST0, llvm::Instruction::FAdd))
FPU_TRANSLATION(DIVR_F32m, true, true, true, true,
    (doFOpMR<32, true>(ip, block, X86::ST0, mem_src, X86::DIVR_F32m, llvm::Instruction::FDiv)))
FPU_TRANSLATION(DIVR_F64m, true, true, true, true,
    (doFOpMR<64, true>(ip, block, X86::ST0, mem_src, X86::DIVR_F64m, llvm::Instruction::FDiv)))
FPU_TRANSLATION(DIVR_FI16m, true, true, true, true,
    (doFiOpMR<16, true>(ip, block, X86::ST0, mem_src, X86::DIVR_FI16m, llvm::Instruction::FDiv)))
FPU_TRANSLATION(DIVR_FI32m, true, true, true, true,
    (doFiOpMR<32, true>(ip, block, X86::ST0, mem_src, X86::DIVR_FI32m, llvm::Instruction::FDiv)))
FPU_TRANSLATION(DIVR_FPrST0, true, false, true, false,
    doFOpPRR<false>(ip, block, X86::ST0, OP(0).getReg(), X86::DIVR_FPrST0, llvm::Instruction::FDiv))
FPU_TRANSLATION(DIVR_FST0r, true, false, true, false,
    doFOpRR<false>(ip, block, OP(0).getReg(), X86::ST0, X86::DIVR_FST0r, llvm::Instruction::FDiv))
FPU_TRANSLATION(DIVR_FrST0, true, false, true, false,
    doFOpRR<false>(ip, block, X86::ST0, OP(0).getReg(), X86::DIVR_FrST0, llvm::Instruction::FDiv))
FPU_TRANSLATION(DIV_F32m, true, true, true, true,
    (doFOpMR<32, false>(ip, block, X86::ST0, mem_src, X86::DIV_F32m, llvm::Instruction::FDiv)))
FPU_TRANSLATION(DIV_F64m, true, true, true, true,
    (doFOpMR<64, false>(ip, block, X86::ST0, mem_src, X86::DIV_F64m, llvm::Instruction::FDiv)))
FPU_TRANSLATION(DIV_FI16m, true, true, true, true,
    (doFiOpMR<16, false>(ip, block, X86::ST0, mem_src, X86::DIV_FI16m, llvm::Instruction::FDiv))
    )
FPU_TRANSLATION(DIV_FI32m, true, true, true, true,
    (doFiOpMR<32, false>(ip, block, X86::ST0, mem_src, X86::DIV_FI32m, llvm::Instruction::FDiv))
    )
FPU_TRANSLATION(DIV_FPrST0, true, false, true, false,
    doFOpPRR<true>(ip, block, X86::ST0, OP(0).getReg(), X86::DIV_FPrST0, llvm::Instruction::FDiv))
FPU_TRANSLATION(DIV_FST0r, true, false, true, false,
    doFOpRR<true>(ip, block, OP(0).getReg(), X86::ST0, X86::DIV_FST0r, llvm::Instruction::FDiv))
FPU_TRANSLATION(DIV_FrST0, true, false, true, false,
    doFOpRR<true>(ip, block, X86::ST0, OP(0).getReg(), X86::DIV_FrST0, llvm::Instruction::FDiv))
FPU_TRANSLATION(FSTENVm, false, false, true, true, doFstenv(ip, block, mem_src))
FPU_TRANSLATION(LD_F32m, true, true, true, true,
        doFldM<32>(ip, block, mem_src))
FPU_TRANSLATION(LD_F64m, true, true, true, true,
        doFldM<64>(ip, block, mem_src))
FPU_TRANSLATION(LD_F80m, true, true, true, true,
        doFldM<80>(ip, block, mem_src))
FPU_TRANSLATION(LD_Frr, true, false, true, false, doFldR(ip, block, OP(0)))
FPU_TRANSLATION(MUL_F32m, true, true, true, true,
    (doFOpMR<32, false>(ip, block, X86::ST0, mem_src, X86::MUL_F32m, llvm::Instruction::FMul)))
FPU_TRANSLATION(MUL_F64m, true, true, true, true,
    (doFOpMR<64, false>(ip, block, X86::ST0, mem_src, X86::MUL_F64m, llvm::Instruction::FMul)))
FPU_TRANSLATION(MUL_FI16m, true, true, true, true,
    (doFiOpMR<16, false>(ip, block, X86::ST0, mem_src, X86::MUL_FI16m, llvm::Instruction::FMul))
    )
FPU_TRANSLATION(MUL_FI32m, true, true, true, true,
    (doFiOpMR<32, false>(ip, block, X86::ST0, mem_src, X86::MUL_FI32m, llvm::Instruction::FMul))
    )
FPU_TRANSLATION(MUL_FPrST0, true, false, true, false,
    doFOpPRR<false>(ip, block, X86::ST0, OP(0).getReg(), X86::MUL_FPrST0, llvm::Instruction::FMul))
FPU_TRANSLATION(MUL_FST0r, true, false, true, false,
    doFOpRR<false>(ip, block, OP(0).getReg(), X86::ST0, X86::MUL_FST0r, llvm::Instruction::FMul))
FPU_TRANSLATION(MUL_FrST0, true, false, true, false,
    doFOpRR<false>(ip, block, X86::ST0, OP(0).getReg(), X86::MUL_FrST0, llvm::Instruction::FMul))
FPU_TRANSLATION(ST_F32m, true, true, true, true,
        doFstM<32>(ip, block, mem_src))
FPU_TRANSLATION(ST_F64m, true, true, true, true,
        doFstM<64>(ip, block, mem_src))
FPU_TRANSLATION(ST_FP32m, true, true, true, true,
        doFstpM<32>(ip, block, mem_src))
FPU_TRANSLATION(ST_FP64m, true, true, true, true,
        doFstpM<64>(ip, block, mem_src))
FPU_TRANSLATION(ST_FP80m, true, true, true, true,
        doFstpM<80>(ip, block, mem_src))
FPU_TRANSLATION(ST_FPrr, true, false, true, false,
        doFstpR(ip, block, OP(0)))
FPU_TRANSLATION(ST_Frr, true, false, true, false,
        doFstR(ip, block, OP(0)))
FPU_TRANSLATION(SUBR_F32m, true, true, true, true,
    (doFOpMR<32, true>(ip, block, X86::ST0, mem_src, X86::SUBR_F32m, llvm::Instruction::FSub)))
FPU_TRANSLATION(SUBR_F64m, true, true, true, true,
    (doFOpMR<64, true>(ip, block, X86::ST0, mem_src, X86::SUBR_F64m, llvm::Instruction::FSub)))
FPU_TRANSLATION(SUBR_FI16m, true, true, true, true,
    (doFiOpMR<16, true>(ip, block, X86::ST0, mem_src, X86::SUBR_FI16m, llvm::Instruction::FSub)))
FPU_TRANSLATION(SUBR_FI32m, true, true, true, true,
    (doFiOpMR<32, true>(ip, block, X86::ST0, mem_src, X86::SUBR_FI32m, llvm::Instruction::FSub)))
FPU_TRANSLATION(SUBR_FPrST0, true, false, true, false,
    doFOpPRR<true>(ip, block, X86::ST0, OP(0).getReg(), X86::SUBR_FPrST0, llvm::Instruction::FSub))
FPU_TRANSLATION(SUBR_FST0r, true, false, true, false,
    doFOpRR<true>(ip, block, OP(0).getReg(), X86::ST0, X86::SUBR_FST0r, llvm::Instruction::FSub))
FPU_TRANSLATION(SUBR_FrST0, true, false, true, false,
    doFOpRR<true>(ip, block, X86::ST0, OP(0).getReg(), X86::SUBR_FrST0, llvm::Instruction::FSub))
FPU_TRANSLATION(SUB_F32m, true, true, true, true,
    (doFOpMR<32, false>(ip, block, X86::ST0, mem_src, X86::SUB_F32m, llvm::Instruction::FSub)))
FPU_TRANSLATION(SUB_F64m, true, true, true, true,
    (doFOpMR<64, false>(ip, block, X86::ST0, mem_src, X86::SUB_F64m, llvm::Instruction::FSub)))
FPU_TRANSLATION(SUB_FI16m, true, true, true, true,
    (doFiOpMR<16, false>(ip, block, X86::ST0, mem_src, X86::SUB_FI16m, llvm::Instruction::FSub))
    )
FPU_TRANSLATION(SUB_FI32m, true, true, true, true,
    (doFiOpMR<32, false>(ip, block, X86::ST0, mem_src, X86::SUB_FI32m, llvm::Instruction::FSub))
    )
FPU_TRANSLATION(SUB_FPrST0, true, false, true, false,
    doFOpPRR<false>(ip, block, X86::ST0, OP(0).getReg(), X86::SUB_FPrST0, llvm::Instruction::FSub))
FPU_TRANSLATION(SUB_FST0r, true, false, true, false,
    doFOpRR<false>(ip, block, OP(0).getReg(), X86::ST0, X86::SUB_FST0r, llvm::Instruction::FSub))
FPU_TRANSLATION(SUB_FrST0, true, false, true, false,
    doFOpRR<false>(ip, block, X86::ST0, OP(0).getReg(), X86::SUB_FrST0, llvm::Instruction::FSub))

    // take the remainder of ( DST_VAL[st0] / SRC_VAL[st1]), store in st0
FPU_TRANSLATION(FPREM, true, false, true, false,
    doFOpRR<true>(ip, block, X86::ST1, X86::ST0, X86::FPREM, llvm::Instruction::FRem))
FPU_TRANSLATION(FPREM1, true, false, true, false,
    doFOpRR<true>(ip, block, X86::ST1, X86::ST0, X86::FPREM1, llvm::Instruction::FRem))

FPU_TRANSLATION(SIN_F, true, false, true, false, doFsin(ip, block, X86::ST0))

FPU_TRANSLATION(LD_F0, true, false, true, false,
        doFldC(ip, block, 0.0))
FPU_TRANSLATION(LD_F1, true, false, true, false,
        doFldC(ip, block, 1.0))

FPU_TRANSLATION(FLDPI, true, false, true, false,
        doFldC(ip, block, M_PI))
FPU_TRANSLATION(FLDLN2, true, false, true, false,
        doFldC(ip, block, M_LN2))

FPU_TRANSLATION(FLDL2E, true, false, true, false,
        doFldC(ip, block, M_LOG2E))

FPU_TRANSLATION(FLDLG2, true, false, true, false,
        doFldC(ip, block, M_FLDLG2))

FPU_TRANSLATION(ILD_F16m, true, true, true, true,
        doFildM<16>(ip, block, mem_src))
FPU_TRANSLATION(ILD_F32m, true, true, true, true,
        doFildM<32>(ip, block, mem_src))
FPU_TRANSLATION(ILD_F64m, true, true, true, true,
        doFildM<64>(ip, block, mem_src))

FPU_TRANSLATION(FNSTCW16m, false, false, true, true, doFstcw(ip, block, mem_src))
FPU_TRANSLATION(FLDCW16m, false, false, true, true, doFldcw(ip, block, mem_src))

FPU_TRANSLATION(IST_F16m, true, true, true, true,
        doFistM<16>(ip, block, mem_src))
FPU_TRANSLATION(IST_F32m, true, true, true, true,
        doFistM<32>(ip, block, mem_src))

FPU_TRANSLATION(IST_FP16m, true, true, true, true,
        doFistpM<16>(ip, block, mem_src))
FPU_TRANSLATION(IST_FP32m, true, true, true, true,
        doFistpM<32>(ip, block, mem_src))
FPU_TRANSLATION(IST_FP64m, true, true, true, true,
        doFistpM<64>(ip, block, mem_src))

FPU_TRANSLATION(ISTT_FP64m, true, true, true, true,
        doFistTpM<64>(ip, block, mem_src))
FPU_TRANSLATION(ISTT_FP32m, true, true, true, true,
        doFistTpM<32>(ip, block, mem_src))
FPU_TRANSLATION(ISTT_FP16m, true, true, true, true,
        doFistTpM<16>(ip, block, mem_src))

FPU_TRANSLATION(XCH_F, true, false, true, false,
        doFxch(inst, ip, block))

FPU_TRANSLATION(FYL2X, true, false, true, false,
        doFYL2Xx<false>(inst, ip, block))
FPU_TRANSLATION(FYL2XP1, true, false, true, false,
        doFYL2Xx<true>(inst, ip, block))

FPU_TRANSLATION(UCOM_FPPr, true, false, true, false,
        doFucom(ip, block, X86::ST1, 2))
FPU_TRANSLATION(UCOM_FPr, true, false, true, false,
        doFucom(ip, block, OP(0).getReg(), 1))
FPU_TRANSLATION(UCOM_Fr, true, false, true, false,
        doFucom(ip, block, OP(0).getReg(), 0))

FPU_TRANSLATION(UCOM_FIPr, true, false, true, false,
        doFucomi(ip, block, OP(0).getReg(), 1))
FPU_TRANSLATION(UCOM_FIr, true, false, true, false,
        doFucomi(ip, block, OP(0).getReg(), 0))

FPU_TRANSLATION(FNSTSW16r, false, false, true, false,
        doFstswr(ip, block))
FPU_TRANSLATION(FNSTSWm, false, false, true, true,
        doFstswm(ip, block, mem_src))

FPU_TRANSLATION(FRNDINT, true, false, true, false,
        doFRNDINT(inst, ip, block))

FPU_TRANSLATION(F2XM1, true, false, true, false,
        doF2XM1(inst, ip, block))

FPU_TRANSLATION(FSCALE, true, false, true, false,
        doFSCALE(inst, ip, block))

FPU_TRANSLATION(FABS, true, false, true, false,
        doFABS(inst, ip, block))
FPU_TRANSLATION(FSQRT, true, false, true, false,
        doFSQRT(inst, ip, block))
FPU_TRANSLATION(FCOS, true, false, true, false,
        doFCOS(inst, ip, block))
FPU_TRANSLATION(FSINCOS, true, false, true, false,
        doFSINCOS(inst, ip, block))

FPU_TRANSLATION(FINCSTP, true, false, true, false,
        doFINCSTP(inst, ip, block))
FPU_TRANSLATION(FDECSTP, true, false, true, false,
        doFDECSTP(inst, ip, block))

FPU_TRANSLATION(FPTAN, true, false, true, false,
        doFPTAN(inst, ip, block))

FPU_TRANSLATION(CHS_F, true, false, true, false,
        doCHS(inst, ip, block))

static InstTransResult translate_WAIT(NativeModulePtr natM, BasicBlock *&block,
    InstPtr ip, MCInst &inst)
{
    return ContinueBlock;
}

void FPU_populateDispatchMap(DispatchMap &m)
{
    m[X86::ADD_F32m] = translate_ADD_F32m;
    m[X86::ADD_F64m] = translate_ADD_F64m;
    m[X86::ADD_FI16m] = translate_ADD_FI16m;
    m[X86::ADD_FI32m] = translate_ADD_FI32m;
    m[X86::ADD_FPrST0] = translate_ADD_FPrST0;
    m[X86::ADD_FST0r] = translate_ADD_FST0r;
    m[X86::ADD_FrST0] = translate_ADD_FrST0;
    m[X86::DIVR_F32m] = translate_DIVR_F32m;
    m[X86::DIVR_F64m] = translate_DIVR_F64m;
    m[X86::DIVR_FI16m] = translate_DIVR_FI16m;
    m[X86::DIVR_FI32m] = translate_DIVR_FI32m;
    m[X86::DIVR_FPrST0] = translate_DIVR_FPrST0;
    m[X86::DIVR_FST0r] = translate_DIVR_FST0r;
    m[X86::DIVR_FrST0] = translate_DIVR_FrST0;
    m[X86::DIV_F32m] = translate_DIV_F32m;
    m[X86::DIV_F64m] = translate_DIV_F64m;
    m[X86::DIV_FI16m] = translate_DIV_FI16m;
    m[X86::DIV_FI32m] = translate_DIV_FI32m;
    m[X86::DIV_FPrST0] = translate_DIV_FPrST0;
    m[X86::DIV_FST0r] = translate_DIV_FST0r;
    m[X86::DIV_FrST0] = translate_DIV_FrST0;
    m[X86::FSTENVm] = translate_FSTENVm;
    m[X86::LD_F32m] = translate_LD_F32m;
    m[X86::LD_F64m] = translate_LD_F64m;
    m[X86::LD_F80m] = translate_LD_F80m;
    m[X86::LD_Frr] = translate_LD_Frr;
    m[X86::MUL_F32m] = translate_MUL_F32m;
    m[X86::MUL_F64m] = translate_MUL_F64m;
    m[X86::MUL_FI16m] = translate_MUL_FI16m;
    m[X86::MUL_FI32m] = translate_MUL_FI32m;
    m[X86::MUL_FPrST0] = translate_MUL_FPrST0;
    m[X86::MUL_FST0r] = translate_MUL_FST0r;
    m[X86::MUL_FrST0] = translate_MUL_FrST0;
    m[X86::ST_F32m] = translate_ST_F32m;
    m[X86::ST_F64m] = translate_ST_F64m;

    m[X86::IST_FP32m] = translate_IST_FP32m;
    m[X86::IST_FP64m] = translate_IST_FP64m;
    m[X86::IST_F32m] = translate_IST_F32m;
    m[X86::IST_F16m] = translate_IST_F16m;
    m[X86::IST_FP16m] = translate_IST_FP16m;

    m[X86::ISTT_FP64m] = translate_ISTT_FP64m;
    m[X86::ISTT_FP32m] = translate_ISTT_FP32m;
    m[X86::ISTT_FP16m] = translate_ISTT_FP16m;

    m[X86::ST_FP32m] = translate_ST_FP32m;
    m[X86::ST_FP64m] = translate_ST_FP64m;
    m[X86::ST_FP80m] = translate_ST_FP80m;
    m[X86::ST_FPrr] = translate_ST_FPrr;
    m[X86::ST_Frr] = translate_ST_Frr;
    m[X86::SUBR_F32m] = translate_SUBR_F32m;
    m[X86::SUBR_F64m] = translate_SUBR_F64m;
    m[X86::SUBR_FI16m] = translate_SUBR_FI16m;
    m[X86::SUBR_FI32m] = translate_SUBR_FI32m;
    m[X86::SUBR_FPrST0] = translate_SUBR_FPrST0;
    m[X86::SUBR_FST0r] = translate_SUBR_FST0r;
    m[X86::SUBR_FrST0] = translate_SUBR_FrST0;
    m[X86::SUB_F32m] = translate_SUB_F32m;
    m[X86::SUB_F64m] = translate_SUB_F64m;
    m[X86::SUB_FI16m] = translate_SUB_FI16m;
    m[X86::SUB_FI32m] = translate_SUB_FI32m;
    m[X86::SUB_FPrST0] = translate_SUB_FPrST0;
    m[X86::SUB_FST0r] = translate_SUB_FST0r;
    m[X86::SUB_FrST0] = translate_SUB_FrST0;

    m[X86::WAIT] = translate_WAIT;
    m[X86::SIN_F] = translate_SIN_F;
    m[X86::LD_F0] = translate_LD_F0;
    m[X86::LD_F1] = translate_LD_F1;
    m[X86::FLDPI] = translate_FLDPI;
    m[X86::FLDLN2] = translate_FLDLN2;
    m[X86::FLDL2E] = translate_FLDL2E;
    m[X86::FLDLG2] = translate_FLDLG2;

    m[X86::ILD_F16m] = translate_ILD_F16m;
    m[X86::ILD_F32m] = translate_ILD_F32m;
    m[X86::ILD_F64m] = translate_ILD_F64m;
    m[X86::FNSTCW16m] = translate_FNSTCW16m;
    m[X86::FLDCW16m] = translate_FLDCW16m;

    m[X86::XCH_F] = translate_XCH_F;

	m[X86::FYL2X] = translate_FYL2X;
	m[X86::FYL2XP1] = translate_FYL2XP1;

    m[X86::UCOM_FPPr] = translate_UCOM_FPPr;
    m[X86::UCOM_FPr] = translate_UCOM_FPr;
    m[X86::UCOM_Fr] = translate_UCOM_Fr;

    m[X86::UCOM_FIPr] = translate_UCOM_FIPr;
    m[X86::UCOM_FIr] = translate_UCOM_FIr;

    m[X86::FNSTSW16r] = translate_FNSTSW16r;
    m[X86::FNSTSWm] = translate_FNSTSWm;

    m[X86::FRNDINT] = translate_FRNDINT;
    m[X86::F2XM1] = translate_F2XM1;
    m[X86::FSCALE] = translate_FSCALE;

	m[X86::ABS_F] = translate_FABS;
	m[X86::SQRT_F] = translate_FSQRT;
	m[X86::COS_F] = translate_FCOS;
	m[X86::FPTAN] = translate_FPTAN;
	m[X86::FSINCOS] = translate_FSINCOS;

	m[X86::FDECSTP] = translate_FDECSTP;
	m[X86::FINCSTP] = translate_FINCSTP;

	m[X86::FPREM] = translate_FPREM;
	m[X86::FPREM1] = translate_FPREM1;

	m[X86::CHS_F] = translate_CHS_F;
}

