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
#pragma once
#include <string>

template <int width>
llvm::Value *concatInts(llvm::BasicBlock *b, llvm::Value *a1, llvm::Value *a2) {
    TASSERT(width == 8 || width == 16 || width == 32, "");
    llvm::Type    *typeTo = llvm::Type::getIntNTy(b->getContext(), width*2);
    
    TASSERT(typeTo != NULL, "");
    //bitcast a to twice width
	assert(a1->getType()->getScalarSizeInBits() < typeTo->getScalarSizeInBits());
    llvm::Value   *twiceLarger = new llvm::ZExtInst(a1, typeTo, "", b);
    //shift twiceL to the left by width
    llvm::Value   *tlShifted = llvm::BinaryOperator::Create(llvm::Instruction::Shl, 
                                                twiceLarger, 
                                                CONST_V<width*2>(b, width), 
                                                "", 
                                                b);

    //add a2 to the result, after zero-extending a2
    llvm::Value   *a2Larger = new llvm::SExtInst(a2, typeTo, "", b);
    llvm::Value *addRes = 
        llvm::BinaryOperator::CreateOr(tlShifted, a2Larger, "", b);

    return addRes;
}

// Compute a complex address expression, such as
// [0x1245678+eax*4] and return a Value that represents the computation
// result
llvm::Value *getAddrFromExpr( 
        llvm::BasicBlock      *b,
        NativeModulePtr mod,
        const llvm::MCInst &inst,
        InstPtr ip,
        uint32_t which);

// same as the simpler form, see above
namespace x86 {
llvm::Value *getAddrFromExpr( llvm::BasicBlock      *b,
        NativeModulePtr mod,
        const llvm::MCOperand &Obase,
        const llvm::MCOperand &Oscale,
        const llvm::MCOperand &Oindex,
        const int64_t Odisp,
        const llvm::MCOperand &Oseg,
        bool dataOffset);
}

namespace x86_64 {
llvm::Value *getAddrFromExpr( llvm::BasicBlock      *b,
        NativeModulePtr mod,
        const llvm::MCOperand &Obase,
        const llvm::MCOperand &Oscale,
        const llvm::MCOperand &Oindex,
        const int64_t Odisp,
        const llvm::MCOperand &Oseg,
        bool dataOffset);
}
// Convert the number to a constant in LLVM IR
llvm::ConstantInt *CONST_V(llvm::BasicBlock *b, uint64_t val);

// Assume the instruction has a data reference, and
// return a computed pointer to that data reference
llvm::Value* GLOBAL_DATA_OFFSET(llvm::BasicBlock *b, 
        NativeModulePtr mod, 
        InstPtr ip);
 
// this is an alias for getAddressFromExpr, but used when
// we expect the address computation to contain a data reference
llvm::Value *GLOBAL(llvm::BasicBlock *B, 
        NativeModulePtr natM, 
        const llvm::MCInst &inst, 
        InstPtr ip,
        uint32_t which);

// emit an llvm memcpy intrinsic
llvm::Instruction* callMemcpy(llvm::BasicBlock *B, llvm::Value *dest, llvm::Value *src, uint32_t size, 
        uint32_t align=4, bool isVolatile=false);


using namespace llvm;
using namespace std;

bool addrIsInData(VA addr, NativeModulePtr m, VA &base, VA minAddr);

// return a computed pointer to that data reference for 32/64 bit architecture
template <int width>
llvm::Value* GLOBAL_DATA_OFFSET(BasicBlock *b, NativeModulePtr mod , InstPtr ip)
{
    VA  baseGlobal;
    uint64_t off = ip->get_data_offset();

    if( addrIsInData(off, mod, baseGlobal, 0) ) {
        //we should be able to find a reference to this in global data
        Module  *M = b->getParent()->getParent();
        string  sn = "data_0x" + to_string<VA>(baseGlobal, hex);
        Value   *int_adjusted;
        GlobalVariable *gData = M->getNamedGlobal(sn);

        //if we thought it was a global, we should be able to
        //pin it to a global variable we made during module setup
        if( gData == NULL)
            throw TErr(__LINE__, __FILE__, "Global variable not found");

        // since globals are now a structure
        // we cannot simply slice into them.
        // Need to get ptr and then add integer displacement to ptr

        Value   *globalGEPV[] =
            {   ConstantInt::get(Type::getIntNTy(b->getContext(), width), 0),
                ConstantInt::get(Type::getInt32Ty(b->getContext()), 0)};
        Instruction *globalGEP =
            GetElementPtrInst::Create(gData,  globalGEPV, "", b);
        Type    *ty = Type::getIntNTy(b->getContext(), width);
        Value   *intVal = new PtrToIntInst(globalGEP, ty, "", b);
        uint32_t addr_offset = off-baseGlobal;
        int_adjusted = BinaryOperator::CreateAdd(intVal,
                        CONST_V<width>(b, addr_offset), "", b);
        //then, assign this to the outer 'd' so that the rest of the
        //logic picks up on that address instead of another address

        return int_adjusted;
    } else {
        throw TErr(__LINE__, __FILE__, "Address not in data");
        return NULL;
    }
}
