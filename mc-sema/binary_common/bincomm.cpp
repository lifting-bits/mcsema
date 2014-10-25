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
#include <LExcn.h>
#include <stdio.h>
#include <iostream>
#include <fstream>

#include "llvm/ADT/StringSwitch.h"
#include <boost/filesystem.hpp> 

//COFF file headers
#include "llvm/Object/COFF.h"
#include <algorithm>

#include "PETarget.h"
#include "COFFTarget.h"
#include "ELFTarget.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/MD5.h"

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

namespace {
  string MD5File(string filename) {
  int i;
  FILE *inFile = fopen (filename.c_str(), "rb");
  MD5 Hash;
  MD5::MD5Result MD5Res;
  int bytes;
  unsigned char data[1024];

  LASSERT(inFile, "Can't open file for hashing\n");

  while ((bytes = fread (data, 1, 1024, inFile)) != 0)
    Hash.update(data);
  Hash.final(MD5Res);
  SmallString<32> Res;
  MD5::stringifyResult(MD5Res, Res);
  fclose(inFile);
  return Res.str();
  }
}

UnderlyingTarget targetFromExtension(string extension) {
  UnderlyingTarget  t = StringSwitch<UnderlyingTarget>(extension)
    .Case(".obj", COFF_TGT)
    .Case(".exe", PE_TGT)
    .Case(".dll", PE_TGT)
    .Case(".so", ELF_TGT)
    .Case(".o", ELF_TGT)
    .Case("", ELF_TGT) // assume no extension == ELF
    .Case(".bin", RAW_TGT)
    .Default(UNK_TGT);

  LASSERT(t != UNK_TGT, "Unknown extension: "+extension);

  return t;
}

ExecutableContainer *ExecutableContainer::open(string f, const Target *T, string PK) {
  filesystem::path  p(f);
  p = filesystem::canonical(p);
  filesystem::path  extPath = p.extension();

  UnderlyingTarget t = targetFromExtension(extPath.string());
  string hash = MD5File(f);
  ExecutableContainer *exc = NULL;

  switch(t) {
    case PE_TGT:
      exc = new PeTarget(p.string(), T);
      break;

    case COFF_TGT:
      exc = CoffTarget::CreateCoffTarget(p.string(), T);
      break;

    case ELF_TGT:
      exc = ElfTarget::CreateElfTarget(p.string(), T);
      break;

    case UNK_TGT:
    case RAW_TGT:
      throw LErr(__LINE__, __FILE__, "Unsupported format, NIY");
      break;
  default:
    return NULL;
  }

  exc->hash = hash;

  if(PK == "") {
      outs() << "Disassembly not guided by outside facts.\nUse: -p <protobuff>' to feed information to guide the disassembly\n";
  exc->disassembly = NULL;
  }

  else {
  Disassembly disasm;
  fstream input(PK.c_str(), ios::in | ios::binary);
  if (!disasm.ParseFromIstream(&input)) {
    throw LErr(__LINE__, __FILE__, "Failed to parse facts.");
  }
  exc->disassembly = &disasm;
 }



  return exc;
}

