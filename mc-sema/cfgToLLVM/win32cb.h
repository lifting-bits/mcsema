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
#ifndef WIN32CB_H
#define WIN32CB_H

#include <llvm/IR/Module.h>

inline static llvm::Module* addWin32CallbacksToModule(llvm::Module *mod) { return nullptr; }
inline static llvm::Value* win32CallVirtualAlloc(llvm::Value *size, llvm::BasicBlock *b) { return nullptr; }
inline static llvm::Value* win32GetTib(llvm::BasicBlock *b) { return nullptr; }
inline static llvm::Value* win32GetStackSize(llvm::Value *ptr_tib, llvm::BasicBlock *b) { return nullptr; }
inline static llvm::Value* win32CallVirtualFree(llvm::Value *addr_to_free, llvm::BasicBlock *b) { return nullptr; }
inline static llvm::Value* win32SetAllocationBase(llvm::Value *tib_ptr, 
        llvm::BasicBlock *b, 
        llvm::Value *new_base) { return nullptr; }
inline static llvm::Value *win32GetAllocationBase(llvm::Value *tib_ptr, llvm::BasicBlock *b) { return nullptr; }
inline static llvm::Value* win32SetStackLimit(llvm::Value *ptr_tib, 
        llvm::BasicBlock *b, 
        llvm::Value *new_limit) { return nullptr; }
inline static llvm::Value* win32GetStackLimit(llvm::Value *ptr_tib, llvm::BasicBlock *b) { return nullptr; }
inline static llvm::Value* win32SetStackBase(llvm::Value *ptr_tib, llvm::BasicBlock *b, 
        llvm::Value *new_base) { return nullptr; }
inline static llvm::Value* win32GetStackBase(llvm::Value *ptr_tib, llvm::BasicBlock *b) { return nullptr; }

#endif
