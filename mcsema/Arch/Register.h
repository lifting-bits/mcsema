/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MC_SEMA_ARCH_REGISTER_H_
#define MC_SEMA_ARCH_REGISTER_H_

#include <string>

#include <llvm/lib/Target/X86/MCTargetDesc/X86MCTargetDesc.h>

namespace llvm {

class BasicBlock;
class StructType;

namespace X86 {

// TODO(pag): This is kind of a hack. The idea here is that LLVM's register map
//            doesn't include everything that we want to use.
enum : unsigned {
  MCSEMA_REGISTER_LIST_BEGIN =  llvm::X86::NUM_TARGET_REGS + 4096,

  // Arithmetic flags.
  CF,
  PF,
  AF,
  ZF,
  SF,
  OF,
  DF,

  // FPU control and status word stuff.
  FPU_B,
  FPU_FLAG_BUSY = FPU_B,
  FPU_C3,
  FPU_FLAG_C3 = FPU_C3,
  FPU_C2,
  FPU_FLAG_C2 = FPU_C2,
  FPU_C1,
  FPU_FLAG_C1 = FPU_C1,
  FPU_C0,
  FPU_FLAG_C0 = FPU_C0,
  FPU_ES,
  FPU_FLAG_ES = FPU_ES,
  FPU_SF,
  FPU_FLAG_SF = FPU_SF,
  FPU_PE,
  FPU_FLAG_PE = FPU_PE,
  FPU_UE,
  FPU_FLAG_UE = FPU_UE,
  FPU_OE,
  FPU_FLAG_OE = FPU_OE,
  FPU_ZE,
  FPU_FLAG_ZE = FPU_ZE,
  FPU_DE,
  FPU_FLAG_DE = FPU_DE,
  FPU_IE,
  FPU_FLAG_IE = FPU_IE,

  FPU_X,
  FPU_CONTROL_X = FPU_X,
  FPU_RC,
  FPU_CONTROL_RC = FPU_RC,
  FPU_PC,
  FPU_CONTROL_PC = FPU_PC,
  FPU_PM,
  FPU_CONTROL_PM = FPU_PM,
  FPU_UM,
  FPU_CONTROL_UM = FPU_UM,
  FPU_OM,
  FPU_CONTROL_OM = FPU_OM,
  FPU_ZM,
  FPU_CONTROL_ZM = FPU_ZM,
  FPU_DM,
  FPU_CONTROL_DM = FPU_DM,
  FPU_IM,
  FPU_CONTROL_IM = FPU_IM,

  MCSEMA_REGS_MAX
};

}  // namespace X86
}  // namespace llvm

using MCSemaRegs = unsigned;

extern const std::string &(*ArchRegisterName)(MCSemaRegs);
extern MCSemaRegs (*ArchRegisterNumber)(const std::string &);
extern unsigned (*ArchRegisterOffset)(MCSemaRegs);
extern MCSemaRegs (*ArchRegisterParent)(MCSemaRegs);
extern void (*ArchAllocRegisterVars)(llvm::BasicBlock *);
extern unsigned (*ArchRegisterSize)(MCSemaRegs);
extern llvm::StructType *(*ArchRegStateStructType)(void);

#define getRegisterName ArchRegisterName
#define getRegisterFromName ArchRegisterNumber
#define getRegisterOffset ArchRegisterOffset

#endif  // MC_SEMA_ARCH_REGISTER_H_
