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

template<int width>
llvm::Value *getValueForExternal(llvm::Module *M, NativeInstPtr ip,
                                 llvm::BasicBlock *block) {

  llvm::Value *addrInt = NULL;

  if (ip->has_ext_call_target()) {
    std::string target = ip->get_ext_call_target()->getSymbolName();
    llvm::Value *ext_fn = M->getFunction(target);
    TASSERT(ext_fn != NULL, "Could not find external: " + target);
    addrInt = new llvm::PtrToIntInst(
        ext_fn, llvm::Type::getIntNTy(block->getContext(), width), "", block);
  } else if (ip->has_ext_data_ref()) {
    std::string target = ip->get_ext_data_ref()->getSymbolName();
    llvm::GlobalValue *gvar = M->getGlobalVariable(target);
    TASSERT(gvar != NULL, "Could not find external data: " + target);
    std::cout << __FUNCTION__ << ": Found external data ref to: " << target
              << "\n";

    if (SystemOS(M) == llvm::Triple::Win32) {
      gvar->setDLLStorageClass(llvm::GlobalValue::DLLImportStorageClass);
      // sometimes windows will import this directly as the variable instead of
      // as a reference to a variable. But the rest of the code wants a pointer to var
      llvm::Value *toPtr = new llvm::AllocaInst(gvar->getType(), "", block);
      llvm::Value *writeIt = new llvm::StoreInst(gvar, toPtr, block);
      addrInt = new llvm::PtrToIntInst(
          toPtr, llvm::Type::getIntNTy(block->getContext(), width), "", block);
    } else {

      addrInt = new llvm::PtrToIntInst(
          gvar, llvm::Type::getIntNTy(block->getContext(), width), "", block);
    }

  } else {
    throw TErr(__LINE__, __FILE__, "No external refernce to get value for!");
  }

  return addrInt;

}

template<int width>
llvm::Value *concatInts(llvm::BasicBlock *b, llvm::Value *a1, llvm::Value *a2) {
  TASSERT(width == 8 || width == 16 || width == 32 || width == 64, "");
  llvm::Type *typeTo = llvm::Type::getIntNTy(b->getContext(), width * 2);

  TASSERT(typeTo != NULL, "");
  //bitcast a to twice width
  assert(a1->getType()->getScalarSizeInBits() < typeTo->getScalarSizeInBits());
  llvm::Value *twiceLarger = new llvm::ZExtInst(a1, typeTo, "", b);
  //shift twiceL to the left by width
  llvm::Value *tlShifted = llvm::BinaryOperator::Create(
      llvm::Instruction::Shl, twiceLarger, CONST_V<width * 2>(b, width), "", b);

  //add a2 to the result, after zero-extending a2
  llvm::Value *a2Larger = new llvm::SExtInst(a2, typeTo, "", b);
  llvm::Value *addRes = llvm::BinaryOperator::CreateOr(tlShifted, a2Larger, "",
                                                       b);

  return addRes;
}

// Compute a complex address expression, such as
// [0x1245678+eax*4] and return a Value that represents the computation
// result
llvm::Value *getAddrFromExpr(llvm::BasicBlock *b, NativeModulePtr mod,
                             const llvm::MCInst &inst, NativeInstPtr ip,
                             uint32_t which);

bool addrIsInData(VA addr, NativeModulePtr m, VA &base, VA minAddr);

template<int width>
llvm::Value* getGlobalFromOriginalAddr(VA original_addr, NativeModulePtr mod,
                                       VA addr_start, llvm::BasicBlock *b) {
  VA baseGlobal;
  if (addrIsInData(original_addr, mod, baseGlobal, addr_start)) {
    //we should be able to find a reference to this in global data
    llvm::Module *M = b->getParent()->getParent();
    std::string sn = "data_0x" + to_string<VA>(baseGlobal, std::hex);

    llvm::GlobalVariable *gData = M->getNamedGlobal(sn);

    //if we thought it was a global, we should be able to
    //pin it to a global array we made during module setup
    if (gData == NULL)
      throw TErr(__LINE__, __FILE__, "Global variable not found");

    // since globals are now a structure
    // we cannot simply slice into them.
    // Need to get ptr and then add integer displacement to ptr
    //
    llvm::Type *int_ty = llvm::Type::getIntNTy(b->getContext(), width);
    llvm::Value *globalGEPV[] = {llvm::ConstantInt::get(int_ty, 0),
        llvm::ConstantInt::get(llvm::Type::getInt32Ty(b->getContext()), 0)};
    llvm::Instruction *globalGEP = llvm::GetElementPtrInst::Create(gData,
                                                                   globalGEPV,
                                                                   "", b);
    llvm::Value *intVal = new llvm::PtrToIntInst(globalGEP, int_ty, "", b);
    uint64_t addr_offset = original_addr - baseGlobal;
    llvm::Value *int_adjusted = llvm::BinaryOperator::CreateAdd(
        intVal, CONST_V<width>(b, addr_offset), "", b);
    return int_adjusted;
  } else {
    return nullptr;
  }
}

// same as the simpler form, see above
namespace x86 {
llvm::Value *getAddrFromExpr(llvm::BasicBlock *b, NativeModulePtr mod,
                             const llvm::MCOperand &Obase,
                             const llvm::MCOperand &Oscale,
                             const llvm::MCOperand &Oindex, const int64_t Odisp,
                             const llvm::MCOperand &Oseg, bool dataOffset);
}

namespace x86_64 {
llvm::Value *getAddrFromExpr(llvm::BasicBlock *b, NativeModulePtr mod,
                             const llvm::MCOperand &Obase,
                             const llvm::MCOperand &Oscale,
                             const llvm::MCOperand &Oindex, const int64_t Odisp,
                             const llvm::MCOperand &Oseg, bool dataOffset);
}
// Convert the number to a constant in LLVM IR
llvm::ConstantInt *CONST_V(llvm::BasicBlock *b, uint64_t val);

// this is an alias for getAddressFromExpr, but used when
// we expect the address computation to contain a data reference
llvm::Value *MEM_AS_DATA_REF(llvm::BasicBlock *B, NativeModulePtr natM,
                             const llvm::MCInst &inst, NativeInstPtr ip,
                             uint32_t which);

// emit an llvm memcpy intrinsic
llvm::Instruction* callMemcpy(llvm::BasicBlock *B, llvm::Value *dest,
                              llvm::Value *src, uint32_t size, uint32_t align =
                                  4,
                              bool isVolatile = false);

using namespace llvm;
using namespace std;

// return a computed pointer to that data reference for 32/64 bit architecture
template<int width>
llvm::Value* IMM_AS_DATA_REF(llvm::BasicBlock *B, NativeModulePtr mod,
                             NativeInstPtr ip) {
  auto &C = B->getContext();

  TASSERT(width == 32 || width == 64, "Pointer size must be sane");
  VA baseGlobal;
  // off is the displacement part of a memory reference

  if (ip->has_external_ref()) {
    Function *F = B->getParent();
    Value *addrInt = getValueForExternal<width>(F->getParent(), ip, B);
    TASSERT(addrInt != 0, "Could not get external data reference");
    return addrInt;
  }

  if (false == ip->has_imm_reference) {
    throw TErr(__LINE__, __FILE__,
               "Want to use IMM as data ref but have no IMM reference");
  }
  uint64_t off = ip->get_reference(NativeInst::IMMRef);

  if (ip->has_code_ref()) {
    auto callback_fn = ArchAddCallbackDriver(
        B->getParent()->getParent(), ip->get_reference(NativeInst::IMMRef));
    auto addrInt = new llvm::PtrToIntInst(callback_fn,
                                          llvm::Type::getIntNTy(C, width), "",
                                          B);
    return addrInt;

  } else if (addrIsInData(off, mod, baseGlobal, 0)) {
    //we should be able to find a reference to this in global data
    auto M = B->getParent()->getParent();
    std::string sn = "data_0x" + to_string<VA>(baseGlobal, hex);
    llvm::Value *int_adjusted = nullptr;
    auto gData = M->getNamedGlobal(sn);

    //if we thought it was a global, we should be able to
    //pin it to a global variable we made during module setup
    if (gData == NULL)
      throw TErr(__LINE__, __FILE__, "Global variable not found");

    // since globals are now a structure
    // we cannot simply slice into them.
    // Need to get ptr and then add integer displacement to ptr

    llvm::Value *globalGEPV[] = {llvm::ConstantInt::get(
        llvm::Type::getIntNTy(C, width), 0), llvm::ConstantInt::get(
        llvm::Type::getInt32Ty(C), 0)};
    auto globalGEP = llvm::GetElementPtrInst::Create(gData, globalGEPV, "", B);
    auto ty = llvm::Type::getIntNTy(C, width);
    auto intVal = new llvm::PtrToIntInst(globalGEP, ty, "", B);
    uint32_t addr_offset = off - baseGlobal;
    int_adjusted = llvm::BinaryOperator::CreateAdd(
        intVal, CONST_V<width>(B, addr_offset), "", B);
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
                                           NativeInstPtr ip) {

  auto M = b->getParent()->getParent();
  int regWidth = ArchPointerSize(M);
  if (regWidth <= x86::REG_SIZE) {
    return IMM_AS_DATA_REF<32>(b, mod, ip);
  } else {
    return IMM_AS_DATA_REF<64>(b, mod, ip);
  }
}

inline llvm::PointerType *getVoidPtrType(llvm::LLVMContext & C) {
  auto Int8Type = llvm::IntegerType::getInt8Ty(C);
  return llvm::PointerType::getUnqual(Int8Type);
}

template<int width>
static inline llvm::Value *ADDR_NOREF_IMPL(NativeModulePtr natM,
                                           llvm::BasicBlock *b, int x,
                                           NativeInstPtr ip,
                                           const llvm::MCInst &inst) {

  // Turns out this function name is a lie. This case can ref external data
  auto M = b->getParent()->getParent();
  if (ip->has_external_ref()) {
    auto addrInt = getValueForExternal<width>(M, ip, b);
    TASSERT(addrInt != NULL, "Could not get address for external");
    return addrInt;
  }

  if (ArchPointerSize(M) == Pointer32) {
    return x86::getAddrFromExpr(b, natM, inst.getOperand(x + 0),
                                inst.getOperand(x + 1), inst.getOperand(x + 2),
                                inst.getOperand(x + 3).getImm(),
                                inst.getOperand(x + 4), false);
  } else {
    return x86_64::getAddrFromExpr(b, natM, inst.getOperand(x + 0),
                                   inst.getOperand(x + 1),
                                   inst.getOperand(x + 2),
                                   inst.getOperand(x + 3).getImm(),
                                   inst.getOperand(x + 4), false);
  }

}
