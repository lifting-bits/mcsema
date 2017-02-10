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

#include "mcsema/cfgToLLVM/TransExcn.h"

template<int width>
static InstTransResult doRMMov(NativeInstPtr ip, llvm::BasicBlock *b,
                               llvm::Value *srcAddr, const llvm::MCOperand &dst) {
  //MOV <r>, <mem>
  TASSERT(dst.isReg(), "");
  TASSERT(srcAddr != nullptr, "");

  R_WRITE<width>(b, dst.getReg(), M_READ<width>(ip, b, srcAddr));

  return ContinueBlock;
}

template<int width>
static InstTransResult doMRMov(NativeInstPtr ip, llvm::BasicBlock *&b,
                        llvm::Value *dstAddr, const llvm::MCOperand &src) {
  //MOV <mem>, <r>
  TASSERT(src.isReg(), "src is not a register");
  TASSERT(dstAddr != NULL, "Destination addr can't be null");
  M_WRITE<width>(ip, b, dstAddr, R_READ<width>(b, src.getReg()));
  return ContinueBlock;
}

template<int width>
static InstTransResult doRRMov(NativeInstPtr ip, llvm::BasicBlock *b,
                        const llvm::MCOperand &dst,
                        const llvm::MCOperand &src) {
  //MOV <r>, <r>
  TASSERT(src.isReg(), "");
  TASSERT(dst.isReg(), "");
  R_WRITE<width>(b, dst.getReg(), R_READ<width>(b, src.getReg()));
  return ContinueBlock;
}

void MOV_populateDispatchMap(DispatchMap &m);
