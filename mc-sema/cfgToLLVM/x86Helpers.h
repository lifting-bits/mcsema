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
#include "ArchOps.h"

template <int width>
llvm::Value *concatInts(llvm::BasicBlock *b, llvm::Value *a1, llvm::Value *a2) {
    TASSERT(width == 8 || width == 16 || width == 32 || width == 64, "");
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

// this is an alias for getAddressFromExpr, but used when
// we expect the address computation to contain a data reference
llvm::Value *MEM_AS_DATA_REF(llvm::BasicBlock *B, 
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
llvm::Value* IMM_AS_DATA_REF(BasicBlock *b, NativeModulePtr mod , InstPtr ip)
{
    VA  baseGlobal;
    // off is the displacement part of a memory reference
    if(false == ip->has_imm_reference) {
        throw TErr(__LINE__, __FILE__, "Want to use IMM as data ref but have no IMM reference");
    }
    uint64_t off = ip->get_reference(Inst::IMMRef);

    if(ip->has_code_ref()) {
        Value *callback_fn = archMakeCallbackForLocalFunction(
                b->getParent()->getParent(),
                ip->get_reference(Inst::IMMRef));
        Value *addrInt = new PtrToIntInst(
            callback_fn, llvm::Type::getIntNTy(b->getContext(), width), "", b);
        return addrInt;
    } else if( addrIsInData(off, mod, baseGlobal, 0) ) {
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

// Assume the instruction has a data reference, and
// return a computed pointer to that data reference
static inline llvm::Value* IMM_AS_DATA_REF(llvm::BasicBlock *b, 
        NativeModulePtr mod, 
        InstPtr ip)
{
    
	llvm::Module *M = b->getParent()->getParent();
	int regWidth = getPointerSize(M);
    if(regWidth == x86::REG_SIZE) {
        return IMM_AS_DATA_REF<32>(b, mod, ip);
    } else {
        return IMM_AS_DATA_REF<64>(b, mod, ip);
    }
}

inline llvm::PointerType *getVoidPtrType (llvm::LLVMContext & C) {
    llvm::Type * Int8Type  = llvm::IntegerType::getInt8Ty(C);
    return llvm::PointerType::getUnqual(Int8Type);
}

template <int width>
llvm::Value *getValueForExternal(llvm::Module *M, InstPtr ip, llvm::BasicBlock *block) {

    llvm::Value *addrInt = NULL;

    if( ip->has_ext_call_target() ) {
        std::string target = ip->get_ext_call_target()->getSymbolName();
        llvm::Value *ext_fn = M->getFunction(target);
        TASSERT(ext_fn != NULL, "Could not find external: " + target);
        addrInt = new llvm::PtrToIntInst(
                ext_fn, llvm::Type::getIntNTy(block->getContext(), width), "", block);
    } else if (ip->has_ext_data_ref() ) {
        std::string target = ip->get_ext_data_ref()->getSymbolName();
        llvm::Value *gvar = M->getGlobalVariable(target);

        TASSERT(gvar != NULL, "Could not find external data: " + target);

        std::cout << __FUNCTION__ << ": Found external data ref to: " << target << "\n";

        addrInt = new llvm::PtrToIntInst(
                gvar, llvm::Type::getIntNTy(block->getContext(), width), "", block);
        //if(gvar->getType()->isPointerTy()) {
        //    addrInt = getLoadableValue<width>(gvar, block);
        //    TASSERT(addrInt != nullptr, "data ref is of an unloadable pointer type");
        //} else {
        //    llvm::IntegerType *int_t = llvm::dyn_cast<llvm::IntegerType>(gvar->getType());
        //    if( int_t == NULL) {
        //        throw TErr(__LINE__, __FILE__, "NIY: non-integer, non-pointer external data");
        //    }
        //    else if(int_t->getBitWidth() < width) {
        //        addrInt = new llvm::ZExtInst(gvar,
        //                llvm::Type::getIntNTy(block->getContext(), width),
        //                "",
        //                block);
        //    }
        //    else if(int_t->getBitWidth() == width) {
        //        addrInt = gvar;
        //    }
        //    else {
        //        throw TErr(__LINE__, __FILE__, "NIY: external type > width");
        //    }
        //}

    } else {
        throw TErr(__LINE__, __FILE__, "No external refernce to get value for!");
    }

    return addrInt;

}


template <int width>
static inline Value *ADDR_NOREF_IMPL(NativeModulePtr natM, llvm::BasicBlock *b, int x, InstPtr ip, const llvm::MCInst &inst) {
//#define ADDR_NOREF(x) \
//	getPointerSize(block->getParent()->getParent()) == Pointer32 ?	\
//		x86::getAddrFromExpr(block, natM, OP(x+0), OP(x+1), OP(x+2), OP(x+3).getImm(), OP(x+4), false) :\
//		x86_64::getAddrFromExpr(block, natM, OP(x+0), OP(x+1), OP(x+2), OP(x+3).getImm(), OP(x+4), false)
//

    // Turns out this function name is a lie. This case can ref external data
    llvm::Module *M = b->getParent()->getParent();
    if(ip->has_external_ref()) {
        llvm::Value *addrInt = getValueForExternal<width>(M, ip, b);
        TASSERT(addrInt != NULL, "Could not get address for external");
        return addrInt;
    }

    if(getPointerSize(M) == Pointer32) {
		return x86::getAddrFromExpr(b, natM, inst.getOperand(x+0), inst.getOperand(x+1), inst.getOperand(x+2), inst.getOperand(x+3).getImm(), inst.getOperand(x+4), false);
    } else {
		return x86_64::getAddrFromExpr(b, natM, inst.getOperand(x+0), inst.getOperand(x+1), inst.getOperand(x+2), inst.getOperand(x+3).getImm(), inst.getOperand(x+4), false);
    }

}
