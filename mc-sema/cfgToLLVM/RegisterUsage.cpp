/*
Copyright (c) 2015, Trail of Bits
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

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include "llvm/Support/Debug.h"
#include "X86Subtarget.h"
#include "RegisterUsage.h"
#include "TransExcn.h"
#include <stdexcept>
#include <iostream>

#include "../common/to_string.h"

using namespace std;
using namespace llvm;

llvm::Value *tryLookupName(llvm::Function *F, const std::string &name) {
  for (auto &I : F->front()) {
    if (I.getName() == name) {
      return &I;
    }
  }
  return nullptr;
}

namespace {

#define STR__(x) #x
#define STR_(x) STR__(x)
#define STR(x) STR_(x)

static std::map<MCSemaRegs, RegInfo> REG_TO_OFFSET_MAP {
    {EIP, {0, "XIP"}},
    {RIP, {0, "XIP"}},

    {EAX, {1, "XAX"}},
    {RAX, {1, "XAX"}},

    {EBX, {2, "XBX"}},
    {RBX, {2, "XBX"}},

    {ECX, {3, "XCX"}},
    {RCX, {3, "XCX"}},

    {EDX, {4, "XDX"}},
    {RDX, {4, "XDX"}},

    {SIL, {5, "XSI"}},
    {ESI, {5, "XSI"}},
    {RSI, {5, "XSI"}},

    {DIL, {6, "XDI"}},
    {EDI, {6, "XDI"}},
    {RDI, {6, "XDI"}},

    {ESP, {7, "XSP"}},
    {RSP, {7, "XSP"}},

    {EBP, {8, "XBP"}},
    {RBP, {8, "XBP"}},

    {CF, {9, "CF"}},
    {PF, {10, "PF"}},
    {AF, {11, "AF"}},
    {ZF, {12, "ZF"}},
    {SF, {13, "SF"}},
    {OF, {14, "OF"}},
    {DF, {15, "DF"}},

    {ST0, {16, "STi"}},
    {ST1, {16, "STi"}},
    {ST2, {16, "STi"}},
    {ST3, {16, "STi"}},
    {ST4, {16, "STi"}},
    {ST5, {16, "STi"}},
    {ST6, {16, "STi"}},
    {ST7, {16, "STi"}},

    {FPU_B, {17, "FPU_FLAG_BUSY"}},
    {FPU_C3, {18, "FPU_FLAG_C3"}},
    {FPU_TOP, {19, "FPU_FLAG_TOP"}},
    {FPU_C2, {20, "FPU_FLAG_C2"}},
    {FPU_C1, {21, "FPU_FLAG_C1"}},
    {FPU_C0, {22, "FPU_FLAG_C0"}},
    {FPU_ES, {23, "FPU_FLAG_ES"}},
    {FPU_SF, {24, "FPU_FLAG_SF"}},
    {FPU_PE, {25, "FPU_FLAG_PE"}},
    {FPU_UE, {26, "FPU_FLAG_UE"}},
    {FPU_OE, {27, "FPU_FLAG_OE"}},
    {FPU_ZE, {28, "FPU_FLAG_ZE"}},
    {FPU_DE, {29, "FPU_FLAG_DE"}},
    {FPU_IE, {30, "FPU_FLAG_IE"}},

    {FPU_X, {31, "FPU_CONTROL_X"}},
    {FPU_RC, {32, "FPU_CONTROL_RC"}},
    {FPU_PC, {33, "FPU_CONTROL_PC"}},
    {FPU_PM, {34, "FPU_CONTROL_PM"}},
    {FPU_UM, {35, "FPU_CONTROL_UM"}},
    {FPU_OM, {36, "FPU_CONTROL_OM"}},
    {FPU_ZM, {37, "FPU_CONTROL_ZM"}},
    {FPU_DM, {38, "FPU_CONTROL_DM"}},
    {FPU_IM, {39, "FPU_CONTROL_IM"}},

    {FPU_TAG, {40, "FPU_TAG"}},

    {FPU_LASTIP_SEG, {41, "FPU_LASTIP_SEG"}},
    {FPU_LASTIP_OFF, {42, "FPU_LASTIP_OFF"}},

    {FPU_LASTDATA_SEG, {43, "FPU_LASTDATA_SEG"}},
    {FPU_LASTDATA_OFF, {44, "FPU_LASTDATA_OFF"}},

    {FPU_FOPCODE, {45, "FPU_FOPCODE"}},

    {XMM0, {46, "XMM0"}},
    {XMM1, {47, "XMM1"}},
    {XMM2, {48, "XMM2"}},
    {XMM3, {49, "XMM3"}},
    {XMM4, {50, "XMM4"}},
    {XMM5, {51, "XMM5"}},
    {XMM6, {52, "XMM6"}},
    {XMM7, {53, "XMM7"}},
    {XMM8, {54, "XMM8"}},
    {XMM9, {55, "XMM9"}},
    {XMM10, {56, "XMM10"}},
    {XMM11, {57, "XMM11"}},
    {XMM12, {58, "XMM12"}},
    {XMM13, {59, "XMM13"}},
    {XMM14, {60, "XMM14"}},
    {XMM15, {61, "XMM15"}},

    {STACK_BASE, {62, "STACK_BASE"}},
    {STACK_LIMIT, {63, "STACK_LIMIT"}},

    // 32-bit translations don't use these, that's why they appear at the
    // end of the `RegState` struct.
    {R8,  {64, "R8"}},
    {R9,  {65, "R9"}},
    {R10, {66, "R10"}},
    {R11, {67, "R11"}},
    {R12, {68, "R12"}},
    {R13, {69, "R13"}},
    {R14, {70, "R14"}},
    {R15, {71, "R15"}},
};

}  // namespace

namespace x86 {

static std::map<std::string, MCSemaRegs> NAME_TO_REG = {
    {"XIP", EIP},
    {"XAX", EAX},
    {"XBX", EBX},
    {"XCX", ECX},
    {"XDX", EDX},
    {"XDI", EDI},
    {"XSI", ESI},
    {"XBP", EBP},
    {"XSP", ESP},

    {"EIP", EIP},
    {"EAX", EAX},
    {"EBX", EBX},
    {"ECX", ECX},
    {"EDX", EDX},
    {"ESI", ESI},
    {"EDI", EDI},
    {"ESP", ESP},
    {"EBP", EBP},
    {"CF", CF},
    {"PF", PF},
    {"AF", AF},
    {"ZF", ZF},
    {"SF", SF},
    {"OF", OF},
    {"DF", DF},
    {"STi", ST0}, // NOT A MISTAKE. These},
    {"ST0", ST0}, // NOT A MISTAKE. These},
    {"ST1", ST1}, // are in a separate structure},
    {"ST2", ST2},
    {"ST3", ST3},
    {"ST4", ST4},
    {"ST5", ST5},
    {"ST6", ST6},
    {"ST7", ST7},
    {"FPU_FLAG_BUSY", FPU_B},
    {"FPU_FLAG_C3", FPU_C3},
    {"FPU_FLAG_TOP", FPU_TOP},
    {"FPU_FLAG_C2", FPU_C2},
    {"FPU_FLAG_C1", FPU_C1},
    {"FPU_FLAG_C0", FPU_C0},
    {"FPU_FLAG_ES", FPU_ES},
    {"FPU_FLAG_SF", FPU_SF},
    {"FPU_FLAG_PE", FPU_PE},
    {"FPU_FLAG_UE", FPU_UE},
    {"FPU_FLAG_OE", FPU_OE},
    {"FPU_FLAG_ZE", FPU_ZE},
    {"FPU_FLAG_DE", FPU_DE},
    {"FPU_FLAG_IE", FPU_IE},
    {"FPU_CONTROL_X", FPU_X},
    {"FPU_CONTROL_RC", FPU_RC},
    {"FPU_CONTROL_PC", FPU_PC},
    {"FPU_CONTROL_PM", FPU_PM},
    {"FPU_CONTROL_UM", FPU_UM},
    {"FPU_CONTROL_OM", FPU_OM},
    {"FPU_CONTROL_ZM", FPU_ZM},
    {"FPU_CONTROL_DM", FPU_DM},
    {"FPU_CONTROL_IM", FPU_IM},
    {"FPU_TAG", FPU_TAG},
    {"FPU_LASTIP_SEG", FPU_LASTIP_SEG},
    {"FPU_LASTIP_OFF", FPU_LASTIP_OFF},
    {"FPU_LASTDATA_SEG", FPU_LASTDATA_SEG},
    {"FPU_LASTDATA_OFF", FPU_LASTDATA_OFF},
    {"FPU_FOPCODE", FPU_FOPCODE},
    {"XMM0", XMM0},
    {"XMM1", XMM1},
    {"XMM2", XMM2},
    {"XMM3", XMM3},
    {"XMM4", XMM4},
    {"XMM5", XMM5},
    {"XMM6", XMM6},
    {"XMM7", XMM7},
    {"XMM8", XMM8},
    {"XMM9", XMM9},
    {"XMM10", XMM10},
    {"XMM11", XMM11},
    {"XMM12", XMM12},
    {"XMM13", XMM13},
    {"XMM14", XMM14},
    {"XMM15", XMM15},
    {"STACK_BASE", STACK_BASE},
    {"STACK_LIMIT", STACK_LIMIT},
};

StringRef getRegisterName(MCSemaRegs reg) {
  try {
    return REG_TO_OFFSET_MAP.at(reg).name;
  } catch (const std::out_of_range &oor) {
    std::cerr << __FILE__ << ":" << __LINE__
              << ": Could not find register name for: " << reg << std::endl;
    std::cerr << oor.what() << std::endl;
    throw;
  }
}

MCSemaRegs getRegisterFromName(const char *name) {
  return NAME_TO_REG[name];
}

int getRegisterOffset(MCSemaRegs reg) {
  try {
    return REG_TO_OFFSET_MAP.at(reg).position;
  } catch (const std::out_of_range &oor) {
    std::cerr << __FILE__ << ":" << __LINE__
              << ": Could not find register offset for: " << reg << std::endl;
    std::cerr << oor.what() << std::endl;
    throw;
  }
}

Value *lookupLocal(Function *F, MCSemaRegs reg) {
  const auto &name = x86::getRegisterName(reg);
  auto local = tryLookupName(F, name);
  if (!local) {
    throw TErr(__LINE__, __FILE__, "local was not found");
  }
  return local;
}

Value *MCRegToValue(BasicBlock *b, unsigned reg) {
  unsigned realReg = reg;
  switch (reg) {
    case X86::AX:
    case X86::AH:
    case X86::AL:
      realReg = X86::EAX;
      break;
    case X86::BX:
    case X86::BH:
    case X86::BL:
      realReg = X86::EBX;
      break;
    case X86::CX:
    case X86::CH:
    case X86::CL:
      realReg = X86::ECX;
      break;
    case X86::DX:
    case X86::DH:
    case X86::DL:
      realReg = X86::EDX;
      break;
    case X86::SI:
      realReg = X86::ESI;
      break;
    case X86::DI:
      realReg = X86::EDI;
      break;
    case X86::SP:
      realReg = X86::ESP;
      break;
    case X86::BP:
      realReg = X86::EBP;
      break;
    case X86::RAX:
      realReg = X86::EAX;
      break;
    case X86::RBX:
      realReg = X86::EBX;
      break;
    case X86::RCX:
      realReg = X86::ECX;
      break;
    case X86::RDX:
      realReg = X86::EDX;
      break;
    case X86::RDI:
      realReg = X86::EDI;
      break;
    case X86::RSI:
      realReg = X86::ESI;
      break;
    case X86::RBP:
      realReg = X86::EBP;
      break;
    case X86::RSP:
      realReg = X86::ESP;
      break;
    case X86::RIP:
      realReg = X86::EIP;
      break;
    default:
      break;
  }
  Function *F = b->getParent();

  return lookupLocal(F, (MCSemaRegs) realReg);
}

}  // namespace x86

namespace x86_64 {

static std::map<std::string, MCSemaRegs> NAME_TO_REG = {
    {"XIP", RIP},
    {"XAX", RAX},
    {"XBX", RBX},
    {"XCX", RCX},
    {"XDX", RDX},
    {"XDI", RDI},
    {"XSI", RSI},
    {"XBP", RBP},
    {"XSP", RSP},

    {"EIP", RIP},
    {"EAX", RAX},
    {"RAX", RAX},
    {"EBX", RBX},
    {"RBX", RBX},
    {"ECX", RCX},
    {"RCX", RCX},
    {"EDX", RDX},
    {"RDX", RDX},
    {"SIL", RSI},
    {"ESI", RSI},
    {"RSI", RSI},
    {"DIL", RDI},
    {"EDI", RDI},
    {"RDI", RDI},
    {"ESP", RSP},
    {"RSP", RSP},
    {"EBP", RBP},
    {"RBP", RBP},
    {"R8", R8},
    {"R9", R9},
    {"R10", R10},
    {"R11", R11},
    {"R12", R12},
    {"R13", R13},
    {"R14", R14},
    {"R15", R15},
    {"RIP", RIP},
    {"CF", CF},
    {"PF", PF},
    {"AF", AF},
    {"ZF", ZF},
    {"SF", SF},
    {"OF", OF},
    {"DF", DF},
    {"STi", ST0},
    {"ST0", ST0},
    {"ST1", ST1},
    {"ST2", ST2},
    {"ST3", ST3},
    {"ST4", ST4},
    {"ST5", ST5},
    {"ST6", ST6},
    {"ST7", ST7},
    {"FPU_FLAG_BUSY", FPU_B},
    {"FPU_FLAG_C3", FPU_C3},
    {"FPU_FLAG_TOP", FPU_TOP},
    {"FPU_FLAG_C2", FPU_C2},
    {"FPU_FLAG_C1", FPU_C1},
    {"FPU_FLAG_C0", FPU_C0},
    {"FPU_FLAG_ES", FPU_ES},
    {"FPU_FLAG_SF", FPU_SF},
    {"FPU_FLAG_PE", FPU_PE},
    {"FPU_FLAG_UE", FPU_UE},
    {"FPU_FLAG_OE", FPU_OE},
    {"FPU_FLAG_ZE", FPU_ZE},
    {"FPU_FLAG_DE", FPU_DE},
    {"FPU_FLAG_IE", FPU_IE},
    {"FPU_CONTROL_X", FPU_X},
    {"FPU_CONTROL_RC", FPU_RC},
    {"FPU_CONTROL_PC", FPU_PC},
    {"FPU_CONTROL_PM", FPU_PM},
    {"FPU_CONTROL_UM", FPU_UM},
    {"FPU_CONTROL_OM", FPU_OM},
    {"FPU_CONTROL_ZM", FPU_ZM},
    {"FPU_CONTROL_DM", FPU_DM},
    {"FPU_CONTROL_IM", FPU_IM},
    {"FPU_TAG", FPU_TAG},
    {"FPU_LASTIP_SEG", FPU_LASTIP_SEG},
    {"FPU_LASTIP_OFF", FPU_LASTIP_OFF},
    {"FPU_LASTDATA_SEG", FPU_LASTDATA_SEG},
    {"FPU_LASTDATA_OFF", FPU_LASTDATA_OFF},
    {"FPU_FOPCODE", FPU_FOPCODE},
    {"XMM0", XMM0},
    {"XMM1", XMM1},
    {"XMM2", XMM2},
    {"XMM3", XMM3},
    {"XMM4", XMM4},
    {"XMM5", XMM5},
    {"XMM6", XMM6},
    {"XMM7", XMM7},
    {"XMM8", XMM8},
    {"XMM9", XMM9},
    {"XMM10", XMM10},
    {"XMM11", XMM11},
    {"XMM12", XMM12},
    {"XMM13", XMM13},
    {"XMM14", XMM14},
    {"XMM15", XMM15},
    {"STACK_BASE", STACK_BASE},
    {"STACK_LIMIT", STACK_LIMIT}
};

StringRef getRegisterName(MCSemaRegs reg) {
  try {
    return REG_TO_OFFSET_MAP.at(reg).name;
  } catch (const std::out_of_range &oor) {
    std::cerr << __FILE__ << ":" << __LINE__
              << ": Could not find register name for: " << reg << std::endl;
    std::cerr << oor.what() << std::endl;
    throw;
  }
}

MCSemaRegs getRegisterFromName(const char *name) {
  return NAME_TO_REG[name];
}

int getRegisterOffset(MCSemaRegs reg) {
  try {
    return REG_TO_OFFSET_MAP.at(reg).position;
  } catch (const std::out_of_range &oor) {
    std::cerr << __FILE__ << ":" << __LINE__
              << ": Could not find register offset for: " << reg << std::endl;
    std::cerr << oor.what() << std::endl;
    throw;
  }
}

Value *lookupLocal(Function *F, MCSemaRegs reg) {
  const auto &name = x86::getRegisterName(reg);
  auto local = tryLookupName(F, name);
  if (!local) {
    throw TErr(__LINE__, __FILE__, "local was not found");
  }
  return local;
}

Value *MCRegToValue(BasicBlock *b, unsigned reg) {
  unsigned realReg = reg;
  switch (reg) {
    case X86::AX:
    case X86::AH:
    case X86::AL:
    case X86::EAX:
      realReg = X86::RAX;
      break;
    case X86::BX:
    case X86::BH:
    case X86::BL:
    case X86::EBX:
      realReg = X86::RBX;
      break;
    case X86::CX:
    case X86::CH:
    case X86::CL:
    case X86::ECX:
      realReg = X86::RCX;
      break;
    case X86::DX:
    case X86::DH:
    case X86::DL:
    case X86::EDX:
      realReg = X86::RDX;
      break;
    case X86::SIL:
    case X86::SI:
    case X86::ESI:
      realReg = X86::RSI;
      break;
    case X86::DIL:
    case X86::DI:
    case X86::EDI:
      realReg = X86::RDI;
      break;
    case X86::SPL:
    case X86::SP:
    case X86::ESP:
      realReg = X86::RSP;
      break;
    case X86::BPL:
    case X86::BP:
    case X86::EBP:
      realReg = X86::RBP;
      break;
    case X86::R8B:
    case X86::R8W:
    case X86::R8D:
    case X86::R8:
      realReg = X86::R8;
      break;
    case X86::R9B:
    case X86::R9W:
    case X86::R9D:
    case X86::R9:
      realReg = X86::R9;
      break;
    case X86::R10B:
    case X86::R10W:
    case X86::R10D:
    case X86::R10:
      realReg = X86::R10;
      break;
    case X86::R11B:
    case X86::R11W:
    case X86::R11D:
    case X86::R11:
      realReg = X86::R11;
      break;
    case X86::R12B:
    case X86::R12W:
    case X86::R12D:
    case X86::R12:
      realReg = X86::R12;
      break;
    case X86::R13B:
    case X86::R13W:
    case X86::R13D:
    case X86::R13:
      realReg = X86::R13;
      break;
    case X86::R14B:
    case X86::R14W:
    case X86::R14D:
    case X86::R14:
      realReg = X86::R14;
      break;
    case X86::R15B:
    case X86::R15W:
    case X86::R15D:
    case X86::R15:
      realReg = X86::R15;
      break;
    default:
      break;
  }
  Function *F = b->getParent();

  return lookupLocal(F, (MCSemaRegs) realReg);
}

}
