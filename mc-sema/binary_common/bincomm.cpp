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
#include "bincomm.h"
#include "ELFTarget.h"
#include <LExcn.h>
#include "llvm/ADT/StringSwitch.h"
#include <boost/filesystem.hpp> 

//COFF file headers
#include "llvm/Object/COFF.h"
#include <algorithm>

#include "PETarget.h"
#include "COFFTarget.h"

using namespace std;
using namespace llvm;
using namespace boost;

enum UnderlyingTarget {
  PE_TGT,
  ELF_TGT,
  COFF_TGT,
  RAW_TGT,
  UNK_TGT
};


UnderlyingTarget targetFromExtension(string extension) {
  UnderlyingTarget  t = StringSwitch<UnderlyingTarget>(extension)
    .Case(".obj", COFF_TGT)
    .Case(".exe", PE_TGT)
    .Case(".dll", PE_TGT)
    .Case(".so", ELF_TGT)
    .Case(".o", ELF_TGT)
    .Case(".bin", RAW_TGT)
    .Default(UNK_TGT);

  LASSERT(t != UNK_TGT, "Unknown extension: "+extension);

  return t;
}

ExecutableContainer *ExecutableContainer::open(string f, const Target *T) {
  filesystem::path  p(f);
  p = filesystem::canonical(p);
  filesystem::path  extPath = p.extension();

  UnderlyingTarget t = targetFromExtension(extPath.string());

  switch(t) {
    case PE_TGT:
      return new PeTarget(p.string(), T);
      break;

    case COFF_TGT:
      return new CoffTarget(p.string(), T);
      break;

    case ELF_TGT:
      return new ElfTarget(p.string(), T);
      break;

    case UNK_TGT:
    case RAW_TGT:
      throw LErr(__LINE__, __FILE__, "Unsupported format, NIY");
      break;
  }

  return NULL;
}
