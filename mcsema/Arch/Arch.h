/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MC_SEMA_ARCH_ARCH_H_
#define MC_SEMA_ARCH_ARCH_H_

#include <string>

#include <llvm/ADT/Triple.h>
#include <llvm/IR/CallingConv.h>
#include <llvm/lib/Target/X86/X86InstrInfo.h>

namespace llvm {

class BasicBlock;
class CallInst;
class Function;
class Module;
class PointerType;
class StructType;
class Value;

namespace X86 {

// TODO(pag): This is kind of a hack. The idea here is that LLVM's opcode map
//            doesn't include some variants of prefixed opcodes, so we'll
//            pretend that it does by "extending" the opcode enum here.
enum : unsigned {
  MCSEMA_OPCODE_LIST_BEGIN = llvm::X86::INSTRUCTION_LIST_END + 4096,

  REPE_CMPSB_32,
  REPE_CMPSW_32,
  REPE_CMPSD_32,
  REPE_CMPSB_64,
  REPE_CMPSW_64,
  REPE_CMPSD_64,
  REPE_CMPSQ_64,

  REPNE_CMPSB_32,
  REPNE_CMPSW_32,
  REPNE_CMPSD_32,
  REPNE_CMPSB_64,
  REPNE_CMPSW_64,
  REPNE_CMPSD_64,
  REPNE_CMPSQ_64,

  REPE_SCASB_32,
  REPE_SCASW_32,
  REPE_SCASD_32,
  REPE_SCASB_64,
  REPE_SCASW_64,
  REPE_SCASD_64,
  REPE_SCASQ_64,

  REPNE_SCASB_32,
  REPNE_SCASW_32,
  REPNE_SCASD_32,
  REPNE_SCASB_64,
  REPNE_SCASW_64,
  REPNE_SCASD_64,
  REPNE_SCASQ_64,

  REP_LODSB_32,
  REP_LODSW_32,
  REP_LODSD_32,
  REP_LODSB_64,
  REP_LODSW_64,
  REP_LODSD_64,
  REP_LODSQ_64,
};

static std::map<unsigned, std::string> gExtendedOpcodeNames = {
  { REPE_CMPSB_32, "REPE_CMPSB_32" },
  { REPE_CMPSW_32, "REPE_CMPSW_32" },
  { REPE_CMPSD_32, "REPE_CMPSD_32" },
  { REPE_CMPSB_64, "REPE_CMPSB_64" },
  { REPE_CMPSW_64, "REPE_CMPSW_64" },
  { REPE_CMPSD_64, "REPE_CMPSD_64" },
  { REPE_CMPSQ_64, "REPE_CMPSQ_64" },

  { REPNE_CMPSB_32, "REPNE_CMPSB_32" },
  { REPNE_CMPSW_32, "REPNE_CMPSW_32" },
  { REPNE_CMPSD_32, "REPNE_CMPSD_32" },
  { REPNE_CMPSB_64, "REPNE_CMPSB_64" },
  { REPNE_CMPSW_64, "REPNE_CMPSW_64" },
  { REPNE_CMPSD_64, "REPNE_CMPSD_64" },
  { REPNE_CMPSQ_64, "REPNE_CMPSQ_64" },

  { REPE_SCASB_32, "REPE_SCASB_32" },
  { REPE_SCASW_32, "REPE_SCASW_32" },
  { REPE_SCASD_32, "REPE_SCASD_32" },
  { REPE_SCASB_64, "REPE_SCASB_64" },
  { REPE_SCASW_64, "REPE_SCASW_64" },
  { REPE_SCASD_64, "REPE_SCASD_64" },
  { REPE_SCASQ_64, "REPE_SCASQ_64" },

  { REPNE_SCASB_32, "REPNE_SCASB_32" },
  { REPNE_SCASW_32, "REPNE_SCASW_32" },
  { REPNE_SCASD_32, "REPNE_SCASD_32" },
  { REPNE_SCASB_64, "REPNE_SCASB_64" },
  { REPNE_SCASW_64, "REPNE_SCASW_64" },
  { REPNE_SCASD_64, "REPNE_SCASD_64" },
  { REPNE_SCASQ_64, "REPNE_SCASQ_64" },

  { REP_LODSB_32, "REP_LODSB_32" },
  { REP_LODSW_32, "REP_LODSW_32" },
  { REP_LODSD_32, "REP_LODSD_32" },
  { REP_LODSB_64, "REP_LODSB_64" },
  { REP_LODSW_64, "REP_LODSW_64" },
  { REP_LODSD_64, "REP_LODSD_64" },
  { REP_LODSQ_64, "REP_LODSQ_64" }
};

}  // namespace X86

class MCInst;

}  // namespace llvm

typedef uint64_t VA;

enum SystemArchType {
  _X86_,
  _X86_64_
};

enum PointerSize {
  Pointer32 = 32,
  Pointer64 = 64
};

bool ListArchSupportedInstructions(const std::string &triple, llvm::raw_ostream &s, bool ListSupported, bool ListUnsupported);

bool InitArch(llvm::LLVMContext *context,
              const std::string &os,
              const std::string &arch);

int ArchAddressSize(void);

const std::string &ArchTriple(void);
const std::string &ArchDataLayout(void);

// Decodes the instruction, and returns the number of bytes decoded.
size_t ArchDecodeInstruction(const uint8_t *bytes, const uint8_t *bytes_end,
                             uintptr_t va, llvm::MCInst &inst);

// Convert the given assembly instruction into an inline ASM operation in lieu
// of decompiling it.
void ArchBuildInlineAsm(llvm::MCInst &inst, llvm::BasicBlock *block);

// Return the default calling convention for code on this architecture.
llvm::CallingConv::ID ArchCallingConv(void);

// Return the LLVM arch type of the code we're lifting.
llvm::Triple::ArchType ArchType(void);

// Return the LLVM OS type of the code we're lifting.
llvm::Triple::OSType OSType(void);

// For compatibility.
#define ArchPointerSize(...) ArchAddressSize()
#define ArchGetCallingConv(...) ArchCallingConv()

void ArchInitAttachDetach(llvm::Module *M);

llvm::Function *ArchAddEntryPointDriver(
    llvm::Module *M, const std::string &name, VA entry);

llvm::Function *ArchAddExitPointDriver(llvm::Function *F);

llvm::Function *ArchAddCallbackDriver(llvm::Module *M, VA local_target);

void ArchSetCallingConv(llvm::Module *M, llvm::CallInst *ci);

void ArchSetCallingConv(llvm::Module *M, llvm::Function *F);

llvm::GlobalVariable *archGetImageBase(llvm::Module *M);

#define SystemOS(...) OSType()

SystemArchType SystemArch(llvm::Module *M);

std::string ArchNameMcSemaCall(const std::string &name);

llvm::Value *doSubtractImageBase(llvm::Value *original,
                                 llvm::BasicBlock *block, int width);

template <int width>
inline static llvm::Value *doSubtractImageBase(
    llvm::Value *original, llvm::BasicBlock *block) {
  return doSubtractImageBase(original, block, width);
}

bool shouldSubtractImageBase(llvm::Module *M);

llvm::Value *doSubtractImageBaseInt(llvm::Value *original,
                                    llvm::BasicBlock *block);

#endif  // MC_SEMA_ARCH_ARCH_H_
