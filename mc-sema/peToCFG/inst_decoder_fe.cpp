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
#include "peToCFG.h"
#include "X86.h"
#include <LExcn.h>
#include "../common/to_string.h"
#include "llvm/Support/Debug.h"

using namespace std;
using namespace boost;
using namespace llvm;


InstPtr LLVMByteDecoder::getInstFromBuff(VA addr, llvm::MemoryObject *bmo) {
  InstPtr           inst;
  llvm::MCInst      mcInst;
  ::uint64_t    insLen;
  VA                nextVA = addr;
  ::uint32_t        arch_type;

  uint8_t prefixes[0x100] = {0};

  llvm::MCDisassembler::DecodeStatus  s;


  bool have_prefix = true;
  size_t bmo_size = bmo->getExtent() - bmo->getBase();
  while(have_prefix)
  {
      insLen = 0;
      s = DisAsm->getInstruction( mcInst,
                                  insLen,
                                  *bmo,
                                  ((::uint64_t)nextVA),
                                  llvm::nulls(),
                                  llvm::nulls());

      if(s == llvm::MCDisassembler::Success && bmo_size > 1)
      {
          switch(mcInst.getOpcode()) {
              case llvm::X86::REP_PREFIX:
                  prefixes[0xF3] = 1;
                  break;
              case llvm::X86::REPNE_PREFIX:
                  prefixes[0xF2] = 1;
                  break;
              case llvm::X86::LOCK_PREFIX:
                  prefixes[0xF0] = 1;
                  break;
              default:
                  have_prefix = false;
          }

      } else {
          have_prefix = false;
          break;
      }

      if(have_prefix) {
          nextVA += 1;
      } else {
          for(int i = 0; i < 0x100; i++) {
              if(prefixes[i] == 1) {
                  mcInst.prefixPresent[i] = 1;
              }
          }
          break;
          // set prefixes
      }
  }

  Inst::Prefix    pfx = Inst::NoPrefix;
  if(s == llvm::MCDisassembler::Success) {

    if( mcInst.getOpcode() == llvm::X86::MOVSL && mcInst.hasPrefix(0xF3) ) {
        mcInst.setOpcode(llvm::X86::REP_MOVSD_32);
    } else if( mcInst.hasPrefix(0xF2) ) {
        pfx = Inst::RepNePrefix;
    } else if( mcInst.hasPrefix(0xF3) ) {
        pfx = Inst::RepPrefix;
    } else if ( mcInst.hasPrefix(0x64) ) {
        pfx = Inst::FSPrefix;
    } else if ( mcInst.hasPrefix(0x64) ) {
        pfx = Inst::GSPrefix;
    }

    string                      outS;
    llvm::raw_string_ostream    osOut(outS);
    MCOperand                   oper;

    this->IP->printInst(&mcInst, osOut, "");
    vector<uint8_t>  bytes;
	  //store the bytes from the MO in the inst
	  for(unsigned int i = 0; i < insLen; i++) {
      uint8_t b;
      int     k = bmo->readByte(addr+i, &b);
      LASSERT(k == 0, "Failed to read data when decoder could");
      bytes.push_back(b);
	  }
    inst = InstPtr(new Inst(  addr,
                              insLen,
                              mcInst,
                              osOut.str(),
                              pfx,
                              bytes));

    for (unsigned i = 0; i < mcInst.getNumOperands(); ++i) {
        const MCOperand &Op = mcInst.getOperand(i);

        if (Op.isReg() && Op.getReg() == X86::RIP)
            inst->set_rip_relative(i);
    }


    //ask if this is a jmp, and figure out what the true / false follows are
    switch(mcInst.getOpcode()) {
      case X86::JMP32m:
      case X86::JMP32r:
      case X86::JMP64m:
      case X86::JMP64r:
        inst->set_terminator();
        break;
        //throw LErr(__LINE__, __FILE__, "Branch through register not okay yet");
        //break;
      case X86::RETL:
      case X86::RETIL:
      case X86::RETIQ:
      case X86::RETIW:
      case X86::RETQ:
        inst->set_terminator();
        break;
      case X86::JMP_4:
      case X86::JMP_1:
        oper = mcInst.getOperand(0);
        if(oper.isImm()) {
          nextVA += oper.getImm() + insLen;
          inst->set_tr(nextVA);
        } else {
          throw LErr(__LINE__, __FILE__, "Indirect branches not there yet");
        }
        break;
      case X86::LOOP:
      case X86::LOOPE:
      case X86::LOOPNE:
      case X86::JO_4:
      case X86::JO_1:
      case X86::JNO_4:
      case X86::JNO_1:
      case X86::JB_4:
      case X86::JB_1:
      case X86::JAE_4:
      case X86::JAE_1:
      case X86::JE_4:
      case X86::JE_1:
      case X86::JNE_4:
      case X86::JNE_1:
      case X86::JBE_4:
      case X86::JBE_1:
      case X86::JA_4:
      case X86::JA_1:
      case X86::JS_4:
      case X86::JS_1:
      case X86::JNS_4:
      case X86::JNS_1:
      case X86::JP_4:
      case X86::JP_1:
      case X86::JNP_4:
      case X86::JNP_1:
      case X86::JL_4:
      case X86::JL_1:
      case X86::JGE_4:
      case X86::JGE_1:
      case X86::JLE_4:
      case X86::JLE_1:
      case X86::JG_4:
      case X86::JG_1:
      case X86::JCXZ:
      case X86::JECXZ_32:
      case X86::JRCXZ:
        oper = mcInst.getOperand(0);
        LASSERT(oper.isImm(), "Should not be of this type");
        inst->set_tr(addr + oper.getImm() + insLen);
        inst->set_fa(addr + insLen);
        break;
    }

  } else {
    string  s = to_string<VA>(addr, hex);
    throw LErr(__LINE__, __FILE__, "Failed to decode address 0x"+s);
  }

  return inst;
}
