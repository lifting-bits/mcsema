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
#include "raiseX86.h"
#include "InstructionDispatch.h"
#include "llvm/Support/Debug.h"

using namespace llvm;

#define INSTR_DEBUG(ip) llvm::dbgs() << __FUNCTION__ << "\tRepresentation: " << ip->printInst() << "\n"

//class INSTR_DEBUG;
void MOV_populateDispatchMap(DispatchMap &m);

template <int width, SystemArchType arch>
InstTransResult doMRMov(InstPtr ip, llvm::BasicBlock *&b,
                        llvm::Value           *dstAddr,
                        const llvm::MCOperand &src)
{
    //MOV <mem>, <r>
    TASSERT(src.isReg(), "src is not a register");
    TASSERT(dstAddr != NULL, "Destination addr can't be null");

    M_WRITE<width>(ip, b, dstAddr, R_READ<width>(b, src.getReg()));

    return ContinueBlock;
}

template <int width>
InstTransResult doMRMovBE(InstPtr ip, llvm::BasicBlock *&b,
                        llvm::Value           *dstAddr,
                        const llvm::MCOperand &src)
{
    //MOV <mem>, <r>
    TASSERT(src.isReg(), "src is not a register");
    TASSERT(dstAddr != NULL, "Destination addr can't be null");

    llvm::Value *srcReg = R_READ<width>(b, src.getReg());

    switch(width){
    case 16:
    {
        llvm::Value *o1 = BinaryOperator::CreateLShr(srcReg, CONST_V<width>(b, width/2), "", b);
        llvm::Value *o2 = BinaryOperator::CreateShl(srcReg, CONST_V<width>(b, width/2), "", b);
        srcReg = BinaryOperator::Create(Instruction::Or, o1, o2, "", b);
    }
    break;

    case 32:
    {
        llvm::Value *o1 = BinaryOperator::CreateLShr(srcReg, CONST_V<width>(b, 8), "", b);
        o1 = BinaryOperator::Create(Instruction::And, o1, CONST_V<width>(b, 0xFF00FF), "", b);

        llvm::Value *o2 = BinaryOperator::CreateShl(srcReg, CONST_V<width>(b, 8), "", b);
        o2 = BinaryOperator::Create(Instruction::And, o2, CONST_V<width>(b, 0xFF00FF00), "", b);

        llvm::Value *val = BinaryOperator::Create(Instruction::Or, o1, o2, "", b);

        llvm::Value *val1 = BinaryOperator::CreateLShr(val, CONST_V<width>(b, 16), "", b);
        llvm::Value *val2 = BinaryOperator::CreateShl(val, CONST_V<width>(b, 16), "", b);

        srcReg = BinaryOperator::Create(Instruction::Or, val1, val2, "", b);
    }
    break;

    case 64:
    {
        llvm::Value *o1 = BinaryOperator::CreateLShr(srcReg, CONST_V<width>(b, 8), "", b);
        o1 = BinaryOperator::Create(Instruction::And, o1, CONST_V<width>(b, 0x00FF00FF00FF00FF), "", b);

        llvm::Value *o2 = BinaryOperator::CreateShl(srcReg, CONST_V<width>(b, 8), "", b);
        o2 = BinaryOperator::Create(Instruction::And, o2, CONST_V<width>(b, 0xFF00FF00FF00FF00), "", b);

        llvm::Value *val = BinaryOperator::Create(Instruction::Or, o1, o2, "", b);

        llvm::Value *o3 = BinaryOperator::CreateLShr(val, CONST_V<width>(b, 16), "", b);
        o3 = BinaryOperator::Create(Instruction::And, o3, CONST_V<width>(b, 0x0000FFFF0000FFFF), "", b);

        llvm::Value *o4 = BinaryOperator::CreateShl(val, CONST_V<width>(b, 16), "", b);
        o4 = BinaryOperator::Create(Instruction::And, o3, CONST_V<width>(b, 0xFFFF0000FFFF0000), "", b);

        llvm::Value *val1 = BinaryOperator::Create(Instruction::Or, o3, o4, "", b);

        srcReg = BinaryOperator::Create(Instruction::Or,
                    BinaryOperator::CreateLShr(val1, CONST_V<width>(b, 32), "", b),
                    BinaryOperator::CreateShl(val, CONST_V<width>(b, 32), "", b),
                    "", b);
    }
        break;
    default:
        throw TErr(__LINE__, __FILE__, "Unknown width!");
        break;
    }

    // Does not affect any flags

    M_WRITE<width>(ip, b, dstAddr, srcReg);

    return ContinueBlock;
}

template <int width>
InstTransResult doMRMov(InstPtr ip, llvm::BasicBlock *&b,
                        llvm::Value           *dstAddr,
                        const llvm::MCOperand &src)
{
    //MOV <mem>, <r>
    TASSERT(src.isReg(), "src is not a register");
    TASSERT(dstAddr != NULL, "Destination addr can't be null");

    M_WRITE<width>(ip, b, dstAddr, R_READ<width>(b, src.getReg()));

    return ContinueBlock;
}


template <int width, SystemArchType arch>
InstTransResult doRRMov(InstPtr ip, llvm::BasicBlock *b,
                        const llvm::MCOperand &dst,
                        const llvm::MCOperand &src)
{
    //MOV <r>, <r>
    TASSERT(src.isReg(), "");
    TASSERT(dst.isReg(), "");

    R_WRITE<width, arch>(b, dst.getReg(), R_READ<width>(b, src.getReg()));

    return ContinueBlock;
}

template <int width>
InstTransResult doRRMov(InstPtr ip, llvm::BasicBlock *b,
                        const llvm::MCOperand &dst,
                        const llvm::MCOperand &src)
{
    //MOV <r>, <r>
    TASSERT(src.isReg(), "");
    TASSERT(dst.isReg(), "");
    //pretty straightforward

    R_WRITE<width>(b, dst.getReg(), R_READ<width>(b, src.getReg()));

    return ContinueBlock;
}

template <int width>
InstTransResult doRRMovD(InstPtr ip, llvm::BasicBlock *b,
                        const llvm::MCOperand &dst,
                        const llvm::MCOperand &src)
{
    //MOV <r>, <r>
    TASSERT(src.isReg(), "");
    TASSERT(dst.isReg(), "");
    //pretty straightforward

    R_WRITE<width>(b, dst.getReg(), R_READ<width>(b, src.getReg()));

    return ContinueBlock;
}


template <int width>
InstTransResult doRMMovBE(InstPtr ip, llvm::BasicBlock *&b,
                        llvm::Value           *srcAddr,
                        const llvm::MCOperand &dst)
{
    //MOV <r>, <mem>
    TASSERT(dst.isReg(), "dst is not a register");
    TASSERT(srcAddr != NULL, "Destination addr can't be null");

    llvm::Value *srcVal = M_READ<width>(ip, b, srcAddr);


    switch(width){
    case 16:
    {
        llvm::Value *o1 = BinaryOperator::CreateLShr(srcVal, CONST_V<width>(b, width/2), "", b);
        llvm::Value *o2 = BinaryOperator::CreateShl(srcVal, CONST_V<width>(b, width/2), "", b);
        srcVal = BinaryOperator::Create(Instruction::Or, o1, o2, "", b);
    }
        break;

    case 32:
    {
        llvm::Value *o1 = BinaryOperator::CreateLShr(srcVal, CONST_V<width>(b, 8), "", b);
        o1 = BinaryOperator::Create(Instruction::And, o1, CONST_V<width>(b, 0xFF00FF), "", b);

        llvm::Value *o2 = BinaryOperator::CreateShl(srcVal, CONST_V<width>(b, 8), "", b);
        o2 = BinaryOperator::Create(Instruction::And, o2, CONST_V<width>(b, 0xFF00FF00), "", b);

        llvm::Value *val = BinaryOperator::Create(Instruction::Or, o1, o2, "", b);

        llvm::Value *val1 = BinaryOperator::CreateLShr(val, CONST_V<width>(b, 16), "", b);
        llvm::Value *val2 = BinaryOperator::CreateShl(val, CONST_V<width>(b, 16), "", b);

        srcVal = BinaryOperator::Create(Instruction::Or, val1, val2, "", b);
    }
    break;

    case 64:
    {
        llvm::Value *o1 = BinaryOperator::CreateLShr(srcVal, CONST_V<width>(b, 8), "", b);
        o1 = BinaryOperator::Create(Instruction::And, o1, CONST_V<width>(b, 0x00FF00FF00FF00FF), "", b);

        llvm::Value *o2 = BinaryOperator::CreateShl(srcVal, CONST_V<width>(b, 8), "", b);
        o2 = BinaryOperator::Create(Instruction::And, o2, CONST_V<width>(b, 0xFF00FF00FF00FF00), "", b);

        llvm::Value *val = BinaryOperator::Create(Instruction::Or, o1, o2, "", b);

        llvm::Value *o3 = BinaryOperator::CreateLShr(val, CONST_V<width>(b, 16), "", b);
        o3 = BinaryOperator::Create(Instruction::And, o3, CONST_V<width>(b, 0x0000FFFF0000FFFF), "", b);

        llvm::Value *o4 = BinaryOperator::CreateShl(val, CONST_V<width>(b, 16), "", b);
        o4 = BinaryOperator::Create(Instruction::And, o3, CONST_V<width>(b, 0xFFFF0000FFFF0000), "", b);

        llvm::Value *val1 = BinaryOperator::Create(Instruction::Or, o3, o4, "", b);

        llvm::Value *o5 = BinaryOperator::CreateLShr(val1, CONST_V<width>(b, 32), "", b);

        llvm::Value *o6 = BinaryOperator::CreateShl(val, CONST_V<width>(b, 32), "", b);

        srcVal = BinaryOperator::Create(Instruction::Or, o5, o6, "", b);
    }
        break;
    default:
        throw TErr(__LINE__, __FILE__, "Unknown width!");
        break;
    }

    // Does not affect any flags

    R_WRITE<width>(b, dst.getReg(), srcVal);

    return ContinueBlock;
}


template <int width>
InstTransResult doRMMov(InstPtr ip, llvm::BasicBlock      *b,
                        llvm::Value           *srcAddr,
                        const llvm::MCOperand &dst)
{
    //MOV <r>, <mem>
    TASSERT(dst.isReg(), "");
    TASSERT(srcAddr != NULL, "");

    R_WRITE<width>(b, dst.getReg(), M_READ<width>(ip, b, srcAddr));

    return ContinueBlock;
}

// given a pointer, attempt to load its value into a
// <width> sized integer. 
//
// Will check for pointers to integers and pointers to 
// arrays of size <= width.
template <int width>
static Value* getLoadableValue(Value *ptr, BasicBlock *block) {
    if (! ptr->getType()->isPointerTy()) {
        // not a pointer, can't load it
        std::cout << __FUNCTION__ << ": Can't load value, not a pointer type" << std::endl;
        return nullptr;
    }

    PointerType* ptr_ty = dyn_cast<PointerType>(ptr->getType());

    Type *ut = ptr_ty->getPointerElementType();

    if(ut->isFloatingPointTy()) {
        throw TErr(__LINE__, __FILE__, "NIY: Floating point externs not yet supported");
    }
    
    // check if its an integer of acceptable width
    if(IntegerType *it = dyn_cast<IntegerType>(ut)) {
        unsigned bw = it->getIntegerBitWidth();

        if(bw == width) {
            return  noAliasMCSemaScope(new LoadInst(ptr, "", block));
        } else if(bw < width) {
            Value *to_ext =  noAliasMCSemaScope(new LoadInst(ptr, "", block));
            return  new llvm::ZExtInst(to_ext,
                    llvm::Type::getIntNTy(block->getContext(), width),
                    "",
                    block);
        } else {
            // can't load this -- its bigger than register width
            std::cout << __FUNCTION__ << ": Integer bigger than bitwidth (" << bw << " > " << width << ")" << std::endl;
            return nullptr;
        }
    }

    // check if its an array that we can bitcast as an acceptable integer
    if(ArrayType *arrt = dyn_cast<ArrayType>(ut)) {
        uint64_t elements = arrt->getNumElements();
        Type *elem_t = arrt->getElementType();

        unsigned elem_size = elem_t->getPrimitiveSizeInBits();

        uint64_t total_size = elem_size * elements;

        if (total_size == 0) {
            // not an array of primitives. can't deal with this yet
            std::cout << __FUNCTION__ << ": array has no elements" << std::endl;
            return nullptr;
        } else if (total_size <= width) {

            Type *new_int_ty = 
                    Type::getIntNTy(block->getContext(), total_size);
            Type *new_ptr_ty = PointerType::get(new_int_ty, ptr_ty->getAddressSpace());
            Value *int_ptr = CastInst::CreatePointerCast(ptr, new_ptr_ty, "", block);
            Value *as_int =  noAliasMCSemaScope(new LoadInst(int_ptr, "", block));
            // bitcast to integer
            TASSERT(as_int != NULL, "Can't load pointer");

            if(total_size == width) {
                return as_int;
            }

            // and then zext if its less than width
            return  new llvm::ZExtInst(as_int,
                    llvm::Type::getIntNTy(block->getContext(), width),
                    "",
                    block);


        } else {
            // too big to load
            std::cout << __FUNCTION__ << ": total array size bigger than bitwidth (" << total_size << " > " << width << ")" << std::endl;
            return nullptr;
        }
    }

    throw TErr(__LINE__, __FILE__, "NIY: Unknown external data type");
    return nullptr;
}
