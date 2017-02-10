/*
Copyright (c) 2013, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
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

#include "mcsema/cfgToLLVM/raiseX86.h"

#define OP(x) inst.getOperand(x)

#define ADDR_NOREF(x) \
    ArchPointerSize(block->getParent()->getParent()) == Pointer32 ? \
    ADDR_NOREF_IMPL<32>(natM, block, x, ip, inst) :\
    ADDR_NOREF_IMPL<64>(natM, block, x, ip, inst)

#define CREATE_BLOCK(nm, b) \
    auto block_ ## nm = llvm::BasicBlock::Create( \
        (b)->getContext(), #nm, (b)->getParent())

#define MEM_REFERENCE(which) MEM_AS_DATA_REF(block, natM, inst, ip, which)

#define GENERIC_TRANSLATION_MI(NAME, NOREFS, MEMREF, IMMREF, TWOREFS) \
    static InstTransResult translate_ ## NAME ( \
        TranslationContext &ctx, llvm::BasicBlock *&block) { \
      InstTransResult ret; \
      auto natM = ctx.natM; \
      auto F = ctx.F; \
      auto ip = ctx.natI; \
      auto &inst = ip->get_inst(); \
      if (ip->has_mem_reference && ip->has_imm_reference) { \
          TWOREFS; \
      } else if (ip->has_mem_reference ) { \
          MEMREF; \
      } else if (ip->has_imm_reference ) { \
          IMMREF; \
      } else { \
          NOREFS; \
      } \
      return ContinueBlock;\
    }


#define GENERIC_TRANSLATION_REF(NAME, NOREFS, HASREF) \
    static InstTransResult translate_ ## NAME ( \
        TranslationContext &ctx, llvm::BasicBlock *&block) { \
      InstTransResult ret;\
      auto natM = ctx.natM; \
      auto F = ctx.F; \
      auto ip = ctx.natI; \
      auto &inst = ip->get_inst(); \
      if (ip->has_mem_reference || ip->has_imm_reference || \
         ip->has_external_ref()) { \
          HASREF; \
      } else {\
          NOREFS; \
      } \
      return ContinueBlock; \
    }

#define GENERIC_TRANSLATION(NAME, NOREFS) \
    static InstTransResult translate_ ## NAME ( \
        TranslationContext &ctx, llvm::BasicBlock *&block) { \
      InstTransResult ret;\
      auto natM = ctx.natM; \
      auto F = ctx.F; \
      auto ip = ctx.natI; \
      auto &inst = ip->get_inst(); \
      ret = NOREFS; \
      return ret; \
    }
