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
#include <list>
#include <set>
#include <vector>

#include "TransExcn.h"
#include "llvm/IR/BasicBlock.h"
#include "peToCFG.h"
#include "toModule.h"
#include <llvm/IR/Constants.h>
#include "RegisterUsage.h"
#include "llvm/IR/Module.h"
#include "llvm/ADT/Triple.h"
#include "ArchOps.h"

enum InstTransResult {
  ContinueBlock,
  EndBlock,
  EndCFG,
  TranslateErrorUnsupported,
  TranslateError
};

enum StoreSpillType {
  AllRegs = (1 << 0),   // store/spill all regs
  ABICallStore = (1 << 1),   // store regs in preparation for CALL
  ABICallSpill = (1 << 2),   // spill regs at function prolog
  ABIRetStore = (1 << 3),   // Store regs in preparation for RET
  ABIRetSpill = (1 << 4)    // spill regs right after a RET
};

//type that maps registers to their Value defn in a flow
typedef std::vector<llvm::Value*> regDefT;

//setup code in the first block of the function that defines all of the
//registers via alloca and then copies into them from the structure argument
void setupFlow(llvm::Function *, regDefT &);

llvm::BasicBlock *bbFromStrName(std::string n, llvm::Function *F);

///////////////////////////////////////////////////////////////////////////////
// state modeling functions
///////////////////////////////////////////////////////////////////////////////

llvm::Instruction * noAliasMCSemaScope(llvm::Instruction * inst);
llvm::Instruction * aliasMCSemaScope(llvm::Instruction * inst);

llvm::Value *lookupLocalByName(llvm::Function *F, std::string localName);
void writeLocalsToContext(llvm::BasicBlock *B, unsigned bits,
                          StoreSpillType whichRegs);
void writeContextToLocals(llvm::BasicBlock *B, unsigned bits,
                          StoreSpillType whichRegs);

// Architecture specific utilities are under namespace
namespace x86 {
enum {
  REG_SIZE = 32,
};
llvm::Value *MCRegToValue(llvm::BasicBlock *b, unsigned reg);
int mapPlatRegToOffset(unsigned reg);
int mapStrToGEPOff(std::string regName);
int mapStrToFloatOff(std::string regName);
std::string mapPlatRegToStr(unsigned reg);
}

namespace x86_64 {
enum {
  REG_SIZE = 64,
};
llvm::Value *MCRegToValue(llvm::BasicBlock *b, unsigned reg);
int mapPlatRegToOffset(unsigned reg);
int mapStrToGEPOff(std::string regName);
int mapStrToFloatOff(std::string regName);
std::string mapPlatRegToStr(unsigned reg);
}

template<int width>
llvm::ConstantInt *CONST_V_INT(llvm::LLVMContext &ctx, uint64_t val) {
  llvm::IntegerType *bTy = llvm::Type::getIntNTy(ctx, width);
  return llvm::ConstantInt::get(bTy, val);
}

template<int width>
llvm::ConstantInt *CONST_V(llvm::BasicBlock *b, uint64_t val) {
  llvm::IntegerType *bTy = llvm::Type::getIntNTy(b->getContext(), width);
  return llvm::ConstantInt::get(bTy, val);
}

static llvm::ConstantInt *CONST_V(llvm::BasicBlock *b, uint64_t width,
                                  uint64_t val) {
  llvm::IntegerType *bTy = llvm::Type::getIntNTy(b->getContext(), width);
  return llvm::ConstantInt::get(bTy, val);
}

// Architecture specific register read/write operations defined under namespace;

namespace x86 {

template<int width>
llvm::Value *R_READ(llvm::BasicBlock *b, unsigned reg) {
  //we should return the pointer to the Value object that represents the
  //value read. we'll truncate that value to the width specified by
  //the width parameter.

  //lookup the value that defines the cell that stores the current register
  llvm::Value *localRegVar = x86::MCRegToValue(b, reg);
  if (localRegVar == NULL) {
    throw TErr(__LINE__, __FILE__, "Could not find register");
  }
  //assert(localRegVar != NULL);

  //do a load from this value into a temporary
  llvm::Instruction *tmpVal = noAliasMCSemaScope(
      new llvm::LoadInst(localRegVar, "", b));

  TASSERT(tmpVal != NULL, "Could not read from register");

  llvm::Value *readVal;
  //if the width requested is less than the native bitwidth,
  //then we need to truncate the read
  int regwidth = x86::REG_SIZE;
  if (reg >= llvm::X86::XMM0 && reg <= llvm::X86::XMM7) {
    regwidth = 128;
  }

  if (width < regwidth) {
    llvm::Value *shiftedVal = NULL;
    int readOff = x86::mapPlatRegToOffset(reg);

    if (readOff) {
      //if we are reading from a subreg that is a non-zero
      //offset, we need to do some bitshifting
      shiftedVal = llvm::BinaryOperator::Create(
          llvm::Instruction::LShr, tmpVal, CONST_V<x86::REG_SIZE>(b, readOff),
          "", b);
    } else {
      shiftedVal = tmpVal;
    }

    //then, truncate the shifted value to the appropriate width
    readVal = new llvm::TruncInst(shiftedVal,
                                  llvm::Type::getIntNTy(b->getContext(), width),
                                  "", b);
  } else {
    readVal = tmpVal;
  }

  //return that temporary
  return readVal;
}

template<int width>
void R_WRITE(llvm::BasicBlock *b, unsigned reg, llvm::Value *write) {
  //we don't return anything as this becomes a store

  //lookup the 'stack' local for the register we want to write
  llvm::Value *localRegVar = MCRegToValue(b, reg);
  if (localRegVar == NULL)
    throw TErr(__LINE__, __FILE__, "Could not find register");

  int regwidth = 32;
  if (reg >= llvm::X86::XMM0 && reg <= llvm::X86::XMM7) {
    regwidth = 128;
  }

  llvm::Type *regWidthType = llvm::Type::getIntNTy(b->getContext(), regwidth);

  if (width <= 128 && regwidth == 128) {
    if (regwidth == width) {
      llvm::Instruction *v = noAliasMCSemaScope(
          new llvm::StoreInst(write, localRegVar, b));
      TASSERT(v != NULL, "Cannot make storage instruction")
    } else if (width < 128) {
      llvm::Value *zeros_128 = CONST_V<128>(b, 0);
      llvm::Value *all_ones = llvm::BinaryOperator::CreateNot(zeros_128, "", b);
      // shift 128 bits of 1s to the right
      llvm::Value *shift_right = llvm::BinaryOperator::CreateLShr(
          all_ones, CONST_V<128>(b, 128 - width), "", b);
      // invert the mask, so that only the part we are writing is cleared
      llvm::Value *and_mask = llvm::BinaryOperator::CreateNot(shift_right, "",
                                                              b);
      llvm::Value *fullReg = R_READ<128>(b, reg);

      // mask the value so the parts of the register we don't write
      // is preserved
      llvm::Value *remove_bits = llvm::BinaryOperator::CreateAnd(fullReg,
                                                                 and_mask, "",
                                                                 b);
      llvm::Value *write_z = new llvm::ZExtInst(write, regWidthType, "", b);
      // or the original value with our new parts
      llvm::Value *final_val = llvm::BinaryOperator::CreateOr(remove_bits,
                                                              write_z, "", b);
      // do the write
      llvm::Instruction *v = noAliasMCSemaScope(
          new llvm::StoreInst(final_val, localRegVar, b));
    }
  } else if (width <= 32 && regwidth == 32) {
    if (regwidth == width) {
      llvm::Instruction *v = noAliasMCSemaScope(
          new llvm::StoreInst(write, localRegVar, b));
      TASSERT(v != NULL, "Cannot make storage instruction")
    } else if (width < 32) {
      //we need to model this as a write of a specific offset and width
      int writeOff = mapPlatRegToOffset(reg);
      llvm::Value *maskVal;
      llvm::Value *addVal;

      llvm::Value *write_z = new llvm::ZExtInst(
          write, llvm::Type::getInt32Ty(b->getContext()), "", b);

      //maskVal will be whatever the appropriate mask is
      //addVal will be the value in 'write', shifted appropriately
      if (writeOff) {
        //this is a write to a high offset + some width, so,
        //shift the mask and add values to the left by writeOff
        switch (width) {
          case 8:
            maskVal = CONST_V<32>(b, ~0xFF00);
            addVal = llvm::BinaryOperator::CreateShl(write_z,
                                                     CONST_V<32>(b, writeOff),
                                                     "", b);
            break;

          default:
            throw TErr(__LINE__, __FILE__, "Unsupported bit width in write");
        }
      } else {
        //this is a write to the base + some width
        //simply compute the mask and add values
        switch (width) {
          case 16:
            maskVal = CONST_V<32>(b, ~0xFFFF);
            addVal = write_z;
            break;

          case 8:
            maskVal = CONST_V<32>(b, ~0xFF);
            addVal = write_z;
            break;

          default:
            throw TErr(__LINE__, __FILE__, "Unsupported bit width in write");
        }
      }

      //read the full register
      llvm::Value *fullReg = R_READ<32>(b, reg);

      //AND the value with maskVal
      llvm::Value *andedVal = llvm::BinaryOperator::CreateAnd(fullReg, maskVal,
                                                              "", b);

      //ADD the addVal to the resulting value
      llvm::Value *addedVal = llvm::BinaryOperator::CreateAdd(andedVal, addVal,
                                                              "", b);

      //write this value back into the full-width local
      R_WRITE<32>(b, reg, addedVal);
    }  // width < 32
  } else {  // width <= 32 && register bitwidth == 32
    throw TErr(__LINE__, __FILE__, "Unsupported bit width in write");
  }
  return;
}

}

namespace x86_64 {

template<int width>
llvm::Value *R_READ(llvm::BasicBlock *b, unsigned reg) {
  //we should return the pointer to the Value object that represents the
  //value read. we'll truncate that value to the width specified by
  //the width parameter.

  //lookup the value that defines the cell that stores the current register
  llvm::Value *localRegVar = MCRegToValue(b, reg);
  if (localRegVar == NULL) {
    throw TErr(__LINE__, __FILE__, "Could not find register");
  }
  //assert(localRegVar != NULL);

  //do a load from this value into a temporary
  llvm::Instruction *tmpVal = noAliasMCSemaScope(
      new llvm::LoadInst(localRegVar, "", b));

  TASSERT(tmpVal != NULL, "Could not read from register");

  llvm::Value *readVal;
  //if the width requested is less than the native bitwidth,
  //then we need to truncate the read
  int regwidth = x86_64::REG_SIZE;
  if (reg >= llvm::X86::XMM0 && reg <= llvm::X86::XMM15) {
    regwidth = 128;
  }

  if (width < regwidth) {
    llvm::Value *shiftedVal = NULL;
    int readOff = mapPlatRegToOffset(reg);

    if (readOff) {
      //if we are reading from a subreg that is a non-zero
      //offset, we need to do some bitshifting
      shiftedVal = llvm::BinaryOperator::Create(
          llvm::Instruction::LShr, tmpVal,
          CONST_V<x86_64::REG_SIZE>(b, readOff), "", b);
    } else {
      shiftedVal = tmpVal;
    }

    //then, truncate the shifted value to the appropriate width
    readVal = new llvm::TruncInst(shiftedVal,
                                  llvm::Type::getIntNTy(b->getContext(), width),
                                  "", b);
  } else {
    readVal = tmpVal;
  }

  //return that temporary
  return readVal;
}

template<int width>
void R_WRITE(llvm::BasicBlock *b, unsigned reg, llvm::Value *write) {
  //we don't return anything as this becomes a store

  //lookup the 'stack' local for the register we want to write
  llvm::Value *localRegVar = MCRegToValue(b, reg);
  if (localRegVar == NULL)
    throw TErr(__LINE__, __FILE__, "Could not find register");

  int regwidth = x86_64::REG_SIZE;
  if (reg >= llvm::X86::XMM0 && reg <= llvm::X86::XMM15) {
    regwidth = 128;
  }

  llvm::Type *regWidthType = llvm::Type::getIntNTy(b->getContext(), regwidth);

  if (width <= 128 && regwidth == 128) {
    if (regwidth == width) {
      llvm::Instruction *v = noAliasMCSemaScope(
          new llvm::StoreInst(write, localRegVar, b));
      TASSERT(v != NULL, "Cannot make storage instruction")
    } else if (width < 128) {
      llvm::Value *zeros_128 = CONST_V<128>(b, 0);
      llvm::Value *all_ones = llvm::BinaryOperator::CreateNot(zeros_128, "", b);
      // shift 128 bits of 1s to the right
      llvm::Value *shift_right = llvm::BinaryOperator::CreateLShr(
          all_ones, CONST_V<128>(b, 128 - width), "", b);
      // invert the mask, so that only the part we are writing is cleared
      llvm::Value *and_mask = llvm::BinaryOperator::CreateNot(shift_right, "",
                                                              b);
      llvm::Value *fullReg = R_READ<128>(b, reg);

      // mask the value so the parts of the register we don't write
      // is preserved
      llvm::Value *remove_bits = llvm::BinaryOperator::CreateAnd(fullReg,
                                                                 and_mask, "",
                                                                 b);
      //assert(write->getType()->getScalarSizeInBits() < regWidthType->getScalarSizeInBits());
      llvm::Value *write_z = new llvm::ZExtInst(write, regWidthType, "", b);
      // or the original value with our new parts
      llvm::Value *final_val = llvm::BinaryOperator::CreateOr(remove_bits,
                                                              write_z, "", b);
      // do the write
      llvm::Instruction *v = noAliasMCSemaScope(
          new llvm::StoreInst(final_val, localRegVar, b));
    }
  } else if (width <= x86_64::REG_SIZE && regwidth == x86_64::REG_SIZE) {
    if (regwidth == width) {
      llvm::Instruction *v = noAliasMCSemaScope(
          new llvm::StoreInst(write, localRegVar, b));
      TASSERT(v != NULL, "Cannot make storage instruction")
    } else if (width == x86::REG_SIZE) {

      // write to r32 of r64, zero extend the r32 value and write to 64 bit reg.
      //
      llvm::Value *write_z = new llvm::ZExtInst(
          write, llvm::Type::getInt64Ty(b->getContext()), "", b);

      llvm::Instruction *v = noAliasMCSemaScope(
          new llvm::StoreInst(write_z, localRegVar, b));
      TASSERT(v != NULL, "Cannot make storage instruction")
    } else if (width < x86::REG_SIZE) {
      //we need to model this as a write of a specific offset and width
      int writeOff = mapPlatRegToOffset(reg);
      llvm::Value *maskVal;
      llvm::Value *addVal;

      llvm::Value *write_z = new llvm::ZExtInst(
          write, llvm::Type::getInt64Ty(b->getContext()), "", b);

      //maskVal will be whatever the appropriate mask is
      //addVal will be the value in 'write', shifted appropriately
      if (writeOff) {
        //this is a write to a high offset + some width, so,
        //shift the mask and add values to the left by writeOff
        switch (width) {
          case 8:
            maskVal = CONST_V<64>(b, ~0xFF00);
            addVal = llvm::BinaryOperator::CreateShl(write_z,
                                                     CONST_V<64>(b, writeOff),
                                                     "", b);
            break;

          default:
            throw TErr(__LINE__, __FILE__, "Unsupported bit width in write");
        }
      } else {
        //this is a write to the base + some width
        //simply compute the mask and add values
        switch (width) {
          case 16:
            maskVal = CONST_V<64>(b, ~0xFFFFULL);
            addVal = write_z;
            break;

          case 8:
            maskVal = CONST_V<64>(b, ~0xFFULL);
            addVal = write_z;
            break;

          default:
            throw TErr(__LINE__, __FILE__, "Unsupported bit width in write");
        }
      }

      //read the full register
      llvm::Value *fullReg = R_READ<64>(b, reg);

      //AND the value with maskVal
      llvm::Value *andedVal = llvm::BinaryOperator::CreateAnd(fullReg, maskVal,
                                                              "", b);

      //ADD the addVal to the resulting value
      llvm::Value *addedVal = llvm::BinaryOperator::CreateAdd(andedVal, addVal,
                                                              "", b);

      //write this value back into the full-width local
      R_WRITE<64>(b, reg, addedVal);
    }  // width < 64
  } else {  // width <= 64 && register bitwidth == 64
    throw TErr(__LINE__, __FILE__, "Unsupported bit width in write");
  }
  return;
}
}

llvm::Value *MCRegToValue(llvm::BasicBlock *b, unsigned reg);

template<int width>
void R_WRITE(llvm::BasicBlock *b, unsigned reg, llvm::Value *write) {
  llvm::Module *M = b->getParent()->getParent();
  if (getPointerSize(M) == Pointer32) {
    x86::R_WRITE<width>(b, reg, write);
  } else {
    x86_64::R_WRITE<width>(b, reg, write);
  }
}

template<int width>
llvm::Value *R_READ(llvm::BasicBlock *b, unsigned reg) {
  llvm::Module *M = b->getParent()->getParent();
  if (getPointerSize(M) == Pointer32) {
    return x86::R_READ<width>(b, reg);
  } else {
    return x86_64::R_READ<width>(b, reg);
  }
}

llvm::Value *INTERNAL_M_READ(unsigned width, unsigned addrspace, llvm::BasicBlock *b,
                             llvm::Value *addr);

template<int width>
llvm::Value *M_READ(InstPtr ip, llvm::BasicBlock *b, llvm::Value *addr) {
  return INTERNAL_M_READ(width, ip->get_addr_space(), b, addr);
}

template<int width>
llvm::Value *M_READ_0(llvm::BasicBlock *b, llvm::Value *addr) {
  return INTERNAL_M_READ(width, 0, b, addr);
}

// defined in raiseX86.cpp
void M_WRITE_T(InstPtr ip, llvm::BasicBlock *b, llvm::Value *addr,
               llvm::Value *data, llvm::Type *ptrtype);

void INTERNAL_M_WRITE(int width, unsigned addrspace, llvm::BasicBlock *b,
                      llvm::Value *addr, llvm::Value *data);

template<int width>
void M_WRITE(InstPtr ip, llvm::BasicBlock *b, llvm::Value *addr,
             llvm::Value *data) {
  return INTERNAL_M_WRITE(width, ip->get_addr_space(), b, addr, data);
}

template<int width>
void M_WRITE_0(llvm::BasicBlock *b, llvm::Value *addr, llvm::Value *data) {
  return INTERNAL_M_WRITE(width, 0, b, addr, data);
}

void GENERIC_WRITEREG(llvm::BasicBlock *b, MCSemaRegs reg, llvm::Value *v);
llvm::Value *GENERIC_READREG(llvm::BasicBlock *b, MCSemaRegs reg);

llvm::Value *F_READ(llvm::BasicBlock *b, MCSemaRegs flag);

void F_WRITE(llvm::BasicBlock *b, MCSemaRegs flag, llvm::Value *v);

void F_ZAP(llvm::BasicBlock *b, MCSemaRegs flag);

void F_SET(llvm::BasicBlock *b, MCSemaRegs flag);

void F_CLEAR(llvm::BasicBlock *b, MCSemaRegs flag);

void allocateLocals(llvm::Function *, int);

llvm::BasicBlock *bbFromStrName(std::string, llvm::Function *);

///////////////////////////////////////////////////////////////////////////////
// API usage functions
///////////////////////////////////////////////////////////////////////////////

InstTransResult disInstr(InstPtr ip, llvm::BasicBlock *&block,
                         NativeBlockPtr nb, llvm::Function *F,
                         NativeFunctionPtr natF, NativeModulePtr natM,
                         bool doAnnotation);

llvm::Value *makeCallbackForLocalFunction(llvm::Module *M, VA local_target);

void dataSectionToTypesContents(const std::list<DataSection> &globaldata,
                                DataSection& ds, llvm::Module *M,
                                std::vector<llvm::Constant*>& secContents,
                                std::vector<llvm::Type*>& data_section_types,
                                bool convert_to_callback);

extern bool ignoreUnsupportedInsts;

template<int width, int maskbits>
static void SHR_SET_FLAG_V(llvm::BasicBlock *block, llvm::Value *val,
                           MCSemaRegs flag, llvm::Value *shrbit_val) {
  llvm::Value *shr = llvm::BinaryOperator::CreateLShr(val, shrbit_val, "",
                                                      block);
  llvm::Value *mask_pre = CONST_V<maskbits>(block, 0);
  llvm::Value *mask = llvm::BinaryOperator::CreateNot(mask_pre, "", block);
  llvm::Value *shr_trunc = new llvm::TruncInst(
      shr, llvm::Type::getIntNTy(block->getContext(), maskbits), "", block);

  llvm::Value *anded = llvm::BinaryOperator::CreateAnd(shr_trunc, mask, "",
                                                       block);

  F_WRITE(block, flag, anded);
}

template<int width, int maskbits>
static void SHR_SET_FLAG(llvm::BasicBlock *block, llvm::Value *val,
                         MCSemaRegs flag, int shrbits) {
  SHR_SET_FLAG_V<width, maskbits>(block, val, flag,
                                  CONST_V<width>(block, shrbits));
}
