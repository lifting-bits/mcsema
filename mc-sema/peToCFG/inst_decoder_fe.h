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
#ifndef _INST_FE_H
#define _INST_FE_H

#include "LExcn.h"
#include "llvm/MC/MCContext.h"

#include "X86RegisterInfo.h"
#include "X86InstrBuilder.h"
#include "X86MachineFunctionInfo.h"
#include "X86Subtarget.h"
#include "X86TargetMachine.h"

class LLVMByteDecoder {
private:
  const llvm::MCSubtargetInfo *STI;
  const llvm::MCAsmInfo       *AsmInfo;
  llvm::MCInstPrinter         *IP;
  const llvm::MCDisassembler  *DisAsm;

public:
  LLVMByteDecoder(void)
  {
    const llvm::Target          *target = NULL;
    llvm::MCRegisterInfo        *MRI = NULL;
    const llvm::MCInstrInfo     *MCII = NULL;

    for(llvm::TargetRegistry::iterator it = llvm::TargetRegistry::begin(),
          e = llvm::TargetRegistry::end();
        it != e;
        ++it)
    {
      const llvm::Target  &t = *it;

      if(std::string(t.getName()) == "x86") {
        target= &t;
        break;
      }
    }

    LASSERT( target != NULL, "target != NULL" );

    this->STI = target->createMCSubtargetInfo( "i386-unknown-unknown", "", "");
    MRI = target->createMCRegInfo("i386-unknown-unknown");
    this->AsmInfo = target->createMCAsmInfo(*MRI, "i386-unknown-unknown");

    LASSERT( this->STI, "this->STI" );
    LASSERT( this->AsmInfo, "this->AsmInfo" );

    //get an inst printer
    int AsmPrinterVariant = AsmInfo->getAssemblerDialect();
    MCII = target->createMCInstrInfo();
    this->IP = target->createMCInstPrinter(AsmPrinterVariant,
                                      *AsmInfo,
                                      *MCII,
                                      *MRI,
                                      *STI);
    LASSERT( this->IP, "this->IP" );

    llvm::MCContext *Ctx = new llvm::MCContext(AsmInfo, MRI, nullptr);
    this->DisAsm = target->createMCDisassembler(*this->STI, *Ctx );

    LASSERT( this->DisAsm, "this->DisAsm" );

    return;
  }

  llvm::MCInstPrinter *getPrinter(void) { return this->IP; }
  InstPtr getInstFromBuff(VA, llvm::MemoryObject *);
};
#endif
