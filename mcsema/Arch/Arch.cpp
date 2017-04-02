/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <unordered_set>

#include <llvm/ADT/ArrayRef.h>

#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler.h>

#include <llvm/lib/Target/X86/X86RegisterInfo.h>
#include <llvm/lib/Target/X86/X86InstrBuilder.h>
#include <llvm/lib/Target/X86/X86MachineFunctionInfo.h>

#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/Dispatch.h"
#include "mcsema/Arch/Register.h"

#include "mcsema/cfgToLLVM/TransExcn.h"

namespace {

static std::string gDataLayout;
static std::string gTriple;

static int gAddressSize = 0;

static const llvm::MCDisassembler *gDisassembler = nullptr;

static llvm::CallingConv::ID gCallingConv;
static llvm::Triple::ArchType gArchType;
static llvm::Triple::OSType gOSType;

static DispatchMap gDispatcher;

static bool InitInstructionDecoder(void) {
  std::string errstr;
  auto target = llvm::TargetRegistry::lookupTarget(gTriple, errstr);
  if (!target) {
    llvm::errs() << "Can't find target for " << gTriple << ": " << errstr << "\n";
    return false;
  }

  auto STI = target->createMCSubtargetInfo(gTriple, "", "");
  auto MRI = target->createMCRegInfo(gTriple);
  auto AsmInfo = target->createMCAsmInfo(*MRI, gTriple);
  auto Ctx = new llvm::MCContext(AsmInfo, MRI, nullptr);
  gDisassembler = target->createMCDisassembler(*STI, *Ctx);
  return true;
}

}  // namespace


// Forward declare all of the various x86-specific initializers and
// accessors.
void X86InitRegisterState(llvm::LLVMContext *);
void X86InitInstructionDispatch(DispatchMap &dispatcher);
const std::string &X86RegisterName(MCSemaRegs reg);
MCSemaRegs X86RegisterNumber(const std::string &name);
unsigned X86RegisterOffset(MCSemaRegs reg);
MCSemaRegs X86RegisterParent(MCSemaRegs reg);
void X86AllocRegisterVars(llvm::BasicBlock *);
unsigned X86RegisterSize(MCSemaRegs reg);
llvm::StructType *X86RegStateStructType(void);
llvm::Function *X86GetOrCreateRegStateTracer(llvm::Module *);
llvm::Function *X86GetOrCreateSemantics(llvm::Module *, const std::string &instr);
InstTransResult X86LiftInstruction(
    TranslationContext &, llvm::BasicBlock *&, InstructionLifter *);

// Define the generic arch function pointers.
const std::string &(*ArchRegisterName)(MCSemaRegs) = nullptr;
MCSemaRegs (*ArchRegisterNumber)(const std::string &) = nullptr;
unsigned (*ArchRegisterOffset)(MCSemaRegs) = nullptr;
MCSemaRegs (*ArchRegisterParent)(MCSemaRegs) = nullptr;
void (*ArchAllocRegisterVars)(llvm::BasicBlock *) = nullptr;
unsigned (*ArchRegisterSize)(MCSemaRegs) = nullptr;
llvm::StructType *(*ArchRegStateStructType)(void) = nullptr;
llvm::Function *(*ArchGetOrCreateRegStateTracer)(llvm::Module *) = nullptr;
llvm::Function *(*ArchGetOrCreateSemantics)(llvm::Module *, const std::string &) = nullptr;
InstTransResult (*ArchLiftInstruction)(
    TranslationContext &, llvm::BasicBlock *&, InstructionLifter *) = nullptr;

bool ListArchSupportedInstructions(const std::string &triple, llvm::raw_ostream &s, bool ListSupported, bool ListUnsupported) {
  std::string errstr;
  auto target = llvm::TargetRegistry::lookupTarget(triple, errstr);
  if (!target) {
    llvm::errs() << "Can't find target for " << triple << ": " << errstr << "\n";
    return false;
  }

  llvm::MCInstrInfo *mii = target->createMCInstrInfo();

  if(ListSupported) {
    s << "SUPPORTED INSTRUCTIONS: \n";
    for (auto i : gDispatcher) {
      if (i.first < llvm::X86::INSTRUCTION_LIST_END) {
        s << mii->getName(i.first) << "\n";
      }
      if (i.first > llvm::X86::MCSEMA_OPCODE_LIST_BEGIN &&
          i.first <= llvm::X86::MCSEMA_OPCODE_LIST_BEGIN + llvm::X86::gExtendedOpcodeNames.size()) {
        s << llvm::X86::gExtendedOpcodeNames[i.first] << "\n";
      }
    }
  }

  if (ListUnsupported) {
    s << "UNSUPPORTED INSTRUCTIONS: \n";
    for (int i = llvm::X86::AAA; i < llvm::X86::INSTRUCTION_LIST_END; ++i) {
      if (gDispatcher.end() == gDispatcher.find(i)) {
        s << mii->getName(i) << "\n";
      }
    }
  }
  return true;
}

bool InitArch(llvm::LLVMContext *context, const std::string &os, const std::string &arch) {

  // Windows.
  if (os == "win32") {
    gOSType = llvm::Triple::Win32;
    if (arch == "x86") {
      gArchType = llvm::Triple::x86;
      gCallingConv = llvm::CallingConv::C;
      gAddressSize = 32;
      gTriple = "i686-pc-win32";
      gDataLayout = "e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:"
          "32:32-f64:64:64-f80:128:128-v64:64:64-v128:128:128-a0:0:64-f80:"
          "32:32-n8:16:32-S32";

    } else if (arch == "amd64") {
      gArchType = llvm::Triple::x86_64;
      gCallingConv = llvm::CallingConv::X86_64_Win64;
      gAddressSize = 64;
      gTriple = "x86_64-pc-win32";
      gDataLayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128";
    } else {
      return false;
    }


  // Linux.
  } else if (os == "linux") {
    gOSType = llvm::Triple::Linux;
    if (arch == "x86") {
      gArchType = llvm::Triple::x86;
      gCallingConv = llvm::CallingConv::C;
      gAddressSize = 32;
      gTriple = "i686-pc-linux-gnu";
      gDataLayout = "e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:32:64-f32:"
          "32:32-f64:32:64-v64:64:64-v128:128:128-a0:0:64-f80:32:32-n8:"
          "16:32-S128";

    } else if (arch == "amd64") {
      gArchType = llvm::Triple::x86_64;
      gCallingConv = llvm::CallingConv::X86_64_SysV;
      gAddressSize = 64;
      gTriple = "x86_64-pc-linux-gnu";
      gDataLayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128";

    } else {
      return false;
    }
  } else {
    return false;
  }

  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

  if (arch == "x86" || arch == "amd64") {
    X86InitRegisterState(context);
    X86InitInstructionDispatch(gDispatcher);
    ArchRegisterName = X86RegisterName;
    ArchRegisterNumber = X86RegisterNumber;
    ArchRegisterOffset = X86RegisterOffset;
    ArchRegisterParent = X86RegisterParent;
    ArchRegisterSize = X86RegisterSize;
    ArchAllocRegisterVars = X86AllocRegisterVars;
    ArchRegStateStructType = X86RegStateStructType;
    ArchGetOrCreateRegStateTracer = X86GetOrCreateRegStateTracer;
    ArchGetOrCreateSemantics = X86GetOrCreateSemantics;
    ArchLiftInstruction = X86LiftInstruction;
  } else {
    return false;
  }

  return InitInstructionDecoder();
}

InstructionLifter *ArchGetInstructionLifter(const llvm::MCInst &inst) {
  return gDispatcher[inst.getOpcode()];
}

int ArchAddressSize(void) {
  return gAddressSize;
}

const std::string &ArchTriple(void) {
  return gTriple;
}

const std::string &ArchDataLayout(void) {
  return gDataLayout;
}

namespace {

// Some instructions should be combined with their prefixes. We do this here.
static void FixupInstruction(
    llvm::MCInst &inst, const std::unordered_set<unsigned> &prefixes) {
  static const unsigned fixups[][4] = {
    {llvm::X86::MOVSB, llvm::X86::REP_PREFIX,
        llvm::X86::REP_MOVSB_32, llvm::X86::REP_MOVSB_64},
    {llvm::X86::MOVSW, llvm::X86::REP_PREFIX, llvm::X86::REP_MOVSW_32,
        llvm::X86::REP_MOVSW_64},
    {llvm::X86::MOVSL, llvm::X86::REP_PREFIX, llvm::X86::REP_MOVSD_32,
        llvm::X86::REP_MOVSD_64},
    {llvm::X86::MOVSQ, llvm::X86::REP_PREFIX, 0, llvm::X86::REP_MOVSQ_64},
    {llvm::X86::LODSB, llvm::X86::REP_PREFIX, llvm::X86::REP_LODSB_32,
        llvm::X86::REP_LODSB_64},
    {llvm::X86::LODSW, llvm::X86::REP_PREFIX, llvm::X86::REP_LODSW_32,
        llvm::X86::REP_LODSW_64},
    {llvm::X86::LODSL, llvm::X86::REP_PREFIX, llvm::X86::REP_LODSD_32,
        llvm::X86::REP_LODSD_64},
    {llvm::X86::LODSQ, llvm::X86::REP_PREFIX, 0, llvm::X86::REP_LODSQ_64},
    {llvm::X86::STOSB, llvm::X86::REP_PREFIX, llvm::X86::REP_STOSB_32,
        llvm::X86::REP_STOSB_64},
    {llvm::X86::STOSW, llvm::X86::REP_PREFIX, llvm::X86::REP_STOSW_32,
        llvm::X86::REP_STOSW_64},
    {llvm::X86::STOSL, llvm::X86::REP_PREFIX, llvm::X86::REP_STOSD_32,
        llvm::X86::REP_STOSD_64},
    {llvm::X86::STOSQ, llvm::X86::REP_PREFIX, 0, llvm::X86::REP_STOSQ_64},
    {llvm::X86::CMPSB, llvm::X86::REP_PREFIX, llvm::X86::REPE_CMPSB_32,
        llvm::X86::REPE_CMPSB_64},
    {llvm::X86::CMPSW, llvm::X86::REP_PREFIX, llvm::X86::REPE_CMPSW_32,
        llvm::X86::REPE_CMPSW_64},
    {llvm::X86::CMPSL, llvm::X86::REP_PREFIX, llvm::X86::REPE_CMPSD_32,
        llvm::X86::REPE_CMPSD_64},
    {llvm::X86::CMPSQ, llvm::X86::REP_PREFIX, 0, llvm::X86::REPE_CMPSQ_64},
    {llvm::X86::CMPSB, llvm::X86::REPNE_PREFIX, llvm::X86::REPNE_CMPSB_32,
        llvm::X86::REPNE_CMPSB_64},
    {llvm::X86::CMPSW, llvm::X86::REPNE_PREFIX, llvm::X86::REPNE_CMPSW_32,
        llvm::X86::REPNE_CMPSW_64},
    {llvm::X86::CMPSL, llvm::X86::REPNE_PREFIX, llvm::X86::REPNE_CMPSD_32,
        llvm::X86::REPNE_CMPSD_64},
    {llvm::X86::CMPSQ, llvm::X86::REPNE_PREFIX, 0, llvm::X86::REPNE_CMPSQ_64},
    {llvm::X86::SCASB, llvm::X86::REP_PREFIX, llvm::X86::REPE_SCASB_32,
        llvm::X86::REPE_SCASB_64},
    {llvm::X86::SCASW, llvm::X86::REP_PREFIX, llvm::X86::REPE_SCASW_32,
        llvm::X86::REPE_SCASW_64},
    {llvm::X86::SCASL, llvm::X86::REP_PREFIX, llvm::X86::REPE_SCASD_32,
        llvm::X86::REPE_SCASD_64},
    {llvm::X86::SCASQ, llvm::X86::REP_PREFIX, 0, llvm::X86::REPE_SCASQ_64},
    {llvm::X86::SCASB, llvm::X86::REPNE_PREFIX, llvm::X86::REPNE_SCASB_32,
        llvm::X86::REPNE_SCASB_64},
    {llvm::X86::SCASW, llvm::X86::REPNE_PREFIX, llvm::X86::REPNE_SCASW_32,
        llvm::X86::REPNE_SCASW_64},
    {llvm::X86::SCASL, llvm::X86::REPNE_PREFIX, llvm::X86::REPNE_SCASD_32,
        llvm::X86::REPNE_SCASD_64},
    {llvm::X86::SCASQ, llvm::X86::REPNE_PREFIX, 0, llvm::X86::REPNE_SCASQ_64}
  };

  for (const auto &fixup : fixups) {
    if (inst.getOpcode() == fixup[0] && prefixes.count(fixup[1])) {
      if (32 == gAddressSize) {
        inst.setOpcode(fixup[2]);
      } else {
        inst.setOpcode(fixup[3]);
      }
    }
  }
}

}  // namespace

// Decodes the instruction, and returns the number of bytes decoded.
size_t ArchDecodeInstruction(const uint8_t *bytes, const uint8_t *bytes_end,
                             uintptr_t va, llvm::MCInst &inst) {


  size_t total_size = 0;
  size_t max_size = static_cast<size_t>(bytes_end - bytes);

  std::unordered_set<unsigned> prefixes;

  for (; total_size < max_size; ) {
    llvm::ArrayRef<uint8_t> bytes_to_decode(
        &(bytes[total_size]), max_size - total_size);

    uint64_t size = 0;
    auto decode_status = gDisassembler->getInstruction(
        inst, size, bytes_to_decode, va, llvm::nulls(), llvm::nulls());

    if (llvm::MCDisassembler::Success != decode_status) {
      return 0;
    }

    total_size += size;

    switch (auto op_code = inst.getOpcode()) {
      case llvm::X86::CS_PREFIX:
      case llvm::X86::DATA16_PREFIX:
      case llvm::X86::DS_PREFIX:
      case llvm::X86::ES_PREFIX:
      case llvm::X86::FS_PREFIX:
      case llvm::X86::GS_PREFIX:
      case llvm::X86::LOCK_PREFIX:
      case llvm::X86::REPNE_PREFIX:
      case llvm::X86::REP_PREFIX:
      case llvm::X86::REX64_PREFIX:
      case llvm::X86::SS_PREFIX:
      case llvm::X86::XACQUIRE_PREFIX:
      case llvm::X86::XRELEASE_PREFIX:
        prefixes.insert(op_code);
        break;
      default:
        max_size = 0;  // Stop decoding.
        break;
    }
  }

  FixupInstruction(inst, prefixes);

  return total_size;
}

// Return the default calling convention for code on this architecture.
llvm::CallingConv::ID ArchCallingConv(void) {
  return gCallingConv;
}

// Return the LLVM arch type of the code we're lifting.
llvm::Triple::ArchType ArchType(void) {
  return gArchType;
}

// Return the LLVM OS type of the code we're lifting.
llvm::Triple::OSType OSType(void) {
  return gOSType;
}

SystemArchType SystemArch(llvm::Module *) {
  auto arch = ArchType();
  if (arch == llvm::Triple::x86) {
    return _X86_;
  } else if (arch == llvm::Triple::x86_64) {
    return _X86_64_;
  } else {
    throw TErr(__LINE__, __FILE__, "Unsupported architecture");
  }
}

static void InitADFeatures(llvm::Module *M, const char *name,
                          llvm::FunctionType *EPTy) {
  auto FC = M->getOrInsertFunction(name, EPTy);
  auto F = llvm::dyn_cast<llvm::Function>(FC);
  F->setLinkage(llvm::GlobalValue::ExternalLinkage);
  F->addFnAttr(llvm::Attribute::Naked);
}

void ArchInitAttachDetach(llvm::Module *M) {
  auto &C = M->getContext();
  auto VoidTy = llvm::Type::getVoidTy(C);
  auto EPTy = llvm::FunctionType::get(VoidTy, false);
  const auto OS = SystemOS(M);
  const auto Arch = SystemArch(M);
  if (llvm::Triple::Linux == OS) {
    if (_X86_64_ == Arch) {
      InitADFeatures(M, "__mcsema_attach_call", EPTy);
      InitADFeatures(M, "__mcsema_attach_ret", EPTy);
      InitADFeatures(M, "__mcsema_detach_call", EPTy);
      InitADFeatures(M, "__mcsema_detach_call_value", EPTy);
      InitADFeatures(M, "__mcsema_detach_ret", EPTy);

    } else {
      InitADFeatures(M, "__mcsema_attach_call_cdecl", EPTy);
      InitADFeatures(M, "__mcsema_attach_ret_cdecl", EPTy);
      InitADFeatures(M, "__mcsema_detach_call_cdecl", EPTy);
      InitADFeatures(M, "__mcsema_detach_ret_cdecl", EPTy);
      InitADFeatures(M, "__mcsema_detach_call_value", EPTy);
      InitADFeatures(M, "__mcsema_attach_ret_value", EPTy);

      InitADFeatures(M, "__mcsema_detach_call_stdcall", EPTy);
      InitADFeatures(M, "__mcsema_attach_ret_stdcall", EPTy);
      InitADFeatures(M, "__mcsema_detach_call_fastcall", EPTy);
      InitADFeatures(M, "__mcsema_attach_ret_fastcall", EPTy);
    }
  } else if (llvm::Triple::Win32 == OS) {
    if (_X86_64_ == Arch) {
      InitADFeatures(M, "__mcsema_attach_call", EPTy);
      InitADFeatures(M, "__mcsema_attach_ret", EPTy);
      InitADFeatures(M, "__mcsema_detach_call", EPTy);
      InitADFeatures(M, "__mcsema_detach_call_value", EPTy);
      InitADFeatures(M, "__mcsema_detach_ret", EPTy);
    } else {
      InitADFeatures(M, "__mcsema_attach_call_cdecl", EPTy);
      InitADFeatures(M, "__mcsema_attach_ret_cdecl", EPTy);
      InitADFeatures(M, "__mcsema_detach_call_cdecl", EPTy);
      InitADFeatures(M, "__mcsema_detach_ret_cdecl", EPTy);
      InitADFeatures(M, "__mcsema_detach_call_value", EPTy);
      InitADFeatures(M, "__mcsema_attach_ret_value", EPTy);

      InitADFeatures(M, "__mcsema_detach_call_stdcall", EPTy);
      InitADFeatures(M, "__mcsema_attach_ret_stdcall", EPTy);
      InitADFeatures(M, "__mcsema_detach_call_fastcall", EPTy);
      InitADFeatures(M, "__mcsema_attach_ret_fastcall", EPTy);
    }
  } else {
    TASSERT(false, "Unknown OS Type!");
  }
}

void ArchSetCallingConv(llvm::Module *M, llvm::CallInst *ci) {
  ci->setCallingConv(ArchGetCallingConv(M));
}

void ArchSetCallingConv(llvm::Module *M, llvm::Function *F) {
  F->setCallingConv(ArchGetCallingConv(M));
}

static void LinuxAddPushJumpStub(llvm::Module *M, llvm::Function *F,
                                 llvm::Function *W, const char *stub_handler) {
  auto stub_name = W->getName().str();
  auto stubbed_func_name = F->getName().str();

  std::stringstream as;
  as << "  .globl " << stubbed_func_name << ";\n";
  as << "  .globl " << stub_name << ";\n";
  as << "  .type " << stub_name << ",@function\n";
  as << stub_name << ":\n";
  as << "  .cfi_startproc;\n";
  if (32 == ArchPointerSize(M)) {
    as << "  pushl $" << stubbed_func_name << ";\n";
  } else {
    if (F->isDeclaration()) {
      stubbed_func_name += "@plt";
    }
    as << "  pushq %rax;\n";
    as << "  leaq " << stubbed_func_name << "(%rip), %rax;\n";
    as << "  xchgq (%rsp), %rax;\n";
  }
  as << "  jmp " << stub_handler << ";\n";
  as << "0:\n";
  as << "  .size " << stub_name << ",0b-" << stub_name << ";\n";
  as << "  .cfi_endproc;\n";

  M->appendModuleInlineAsm(as.str());
}

std::string ArchNameMcSemaCall(const std::string &name) {
    return "__mcsema_" + name;
}

static std::string WindowsDecorateName(llvm::Function *F,
                                       const std::string &name) {

  // 64-bit doesn't mangle
  auto M = F->getParent();
  if (64 == ArchPointerSize(M)) {
    return name;
  }

  switch (F->getCallingConv()) {

    case llvm::CallingConv::C:
      return "_" + name;
      break;
    case llvm::CallingConv::X86_StdCall: {
      std::stringstream as;
      int argc = F->arg_size();
      as << "_" << name << "@" << argc * 4;
      return as.str();
    }
      break;
    case llvm::CallingConv::X86_FastCall: {
      std::stringstream as;
      int argc = F->arg_size();
      as << "@" << name << "@" << argc * 4;
      return as.str();
    }
      break;
    default:
      TASSERT(false, "Unsupported Calling Convention for 32-bit Windows")
      ;
      break;
  }
  return "";
}

static void WindowsAddPushJumpStub(bool decorateStub, llvm::Module *M,
                                   llvm::Function *F, llvm::Function *W,
                                   const char *stub_handler) {
  auto stub_name = W->getName().str();
  auto stubbed_func_name = F->getName().str();

  std::stringstream as;
  stubbed_func_name = WindowsDecorateName(F, stubbed_func_name);

  if(decorateStub) {
    stub_name = WindowsDecorateName(W, stub_name);
  }

  as << "  .globl " << stubbed_func_name << ";\n";
  as << "  .globl " << stub_name << ";\n";
  as << stub_name << ":\n";
  as << "  .cfi_startproc;\n";
  if( 32 == ArchPointerSize(M) ) {
    as << "  " << "pushl $" << stubbed_func_name << ";\n";
  } else {
    // use leaq to get rip-relative address of stubbed func
    as << "  " << "pushq %rax\n";
    as << "  " << "leaq " << stubbed_func_name << "(%rip), %rax;\n";
    as << "  " << "xchgq %rax, (%rsp);\n";
  }
  as << "  jmp " << stub_handler << ";\n";
  as << "  .cfi_endproc;\n";

  M->appendModuleInlineAsm(as.str());
}

// Add a function that can be used to transition from native code into lifted
// code.
llvm::Function *ArchAddEntryPointDriver(llvm::Module *M,
                                        const std::string &name, VA entry) {
  //convert the VA into a string name of a function, try and look it up
  std::stringstream ss;
  ss << "sub_" << std::hex << entry;

  auto s = ss.str();
  llvm::Function *F = M->getFunction(s);
  if (!F) {
    llvm::errs() << "Could not find lifted function " << s
                 << " for entry point " << name;
    return nullptr;
  }

  auto &C = F->getContext();
  auto W = M->getFunction(name);
  if (W) {
    return W;
  }

  auto VoidTy = llvm::Type::getVoidTy(C);
  auto WTy = llvm::FunctionType::get(VoidTy, false);
  W = llvm::Function::Create(
      WTy, llvm::GlobalValue::ExternalLinkage, name, M);

  W->addFnAttr(llvm::Attribute::NoInline);
  W->addFnAttr(llvm::Attribute::Naked);

  const auto Arch = SystemArch(M);
  const auto OS = SystemOS(M);

  if (llvm::Triple::Linux == OS) {
    if (_X86_64_ == Arch) {
      LinuxAddPushJumpStub(M, F, W, "__mcsema_attach_call");
    } else {
      LinuxAddPushJumpStub(M, F, W, "__mcsema_attach_call_cdecl");
    }
  } else if (llvm::Triple::Win32 == OS) {
    if (_X86_64_ == Arch) {
      WindowsAddPushJumpStub(true, M, F, W, "__mcsema_attach_call");
    } else {
      WindowsAddPushJumpStub(true, M, F, W, "__mcsema_attach_call_cdecl");
    }
  } else {
    TASSERT(false, "Unsupported OS for entry point driver.");
  }

  F->setLinkage(llvm::GlobalValue::ExternalLinkage);
  if (F->doesNotReturn()) {
    W->setDoesNotReturn();
  }

  return W;
}

// Wrap `F` in a function that will transition from lifted code into native
// code, where `F` is an external reference to a native function.
llvm::Function *ArchAddExitPointDriver(llvm::Function *F) {
  std::stringstream ss;
  auto M = F->getParent();
  const auto OS = SystemOS(M);

  if(llvm::Triple::Win32 == OS) {
      ss << "mcsema_" << F->getName().str();
  } else {
      ss << "_" << F->getName().str();
  }
  auto &C = M->getContext();
  auto name = ss.str();
  auto W = M->getFunction(name);
  if (W) {
    return W;
  }

  W = llvm::Function::Create(F->getFunctionType(),
                             F->getLinkage(), name, M);
  W->setCallingConv(F->getCallingConv());
  W->addFnAttr(llvm::Attribute::NoInline);
  W->addFnAttr(llvm::Attribute::Naked);

  const auto Arch = SystemArch(M);

  if (llvm::Triple::Linux == OS) {
    if (_X86_64_ == Arch) {
      LinuxAddPushJumpStub(M, F, W, "__mcsema_detach_call");
    } else {
      switch (F->getCallingConv()) {
        case llvm::CallingConv::C:
          LinuxAddPushJumpStub(M, F, W, "__mcsema_detach_call_cdecl");
          break;
        case llvm::CallingConv::X86_StdCall:
          LinuxAddPushJumpStub(M, F, W, "__mcsema_detach_call_stdcall");
          break;
        case llvm::CallingConv::X86_FastCall:
          LinuxAddPushJumpStub(M, F, W, "__mcsema_detach_call_fastcall");
          break;
        default:
          TASSERT(false, "Unsupported Calling Convention for 32-bit Linux");
          break;
      }
    }
  } else if (llvm::Triple::Win32 == OS) {

    if (_X86_64_ == Arch) {
        WindowsAddPushJumpStub(true, M, F, W, "__mcsema_detach_call");
    } else {
      switch (F->getCallingConv()) {
        case llvm::CallingConv::C:
          WindowsAddPushJumpStub(true, M, F, W, "__mcsema_detach_call_cdecl");
          break;
        case llvm::CallingConv::X86_StdCall:
          WindowsAddPushJumpStub(true, M, F, W, "__mcsema_detach_call_stdcall");
          break;
        case llvm::CallingConv::X86_FastCall:
          WindowsAddPushJumpStub(true, M, F, W, "__mcsema_detach_call_fastcall");
          break;
        default:
          TASSERT(false, "Unsupported Calling Convention for 32-bit Windows");
          break;
      }
    }
  } else {
    TASSERT(false, "Unsupported OS for exit point driver.");
  }

  if (F->doesNotReturn()) {
    W->setDoesNotReturn();
  }
  return W;
}

llvm::Function *ArchAddCallbackDriver(llvm::Module *M, VA local_target) {
  std::stringstream ss;
  ss << "callback_sub_" << std::hex << local_target;
  auto callback_name = ss.str();
  return ArchAddEntryPointDriver(M, callback_name, local_target);
}

llvm::GlobalVariable *archGetImageBase(llvm::Module *M) {

  // WILL ONLY WORK FOR windows/x86_64
  return M->getNamedGlobal("__ImageBase");
}

bool shouldSubtractImageBase(llvm::Module *M) {

  // we are on windows
  if (llvm::Triple::Win32 != SystemOS(M)) {
    //llvm::errs() << __FUNCTION__ << ": Not on Win32\n";
    return false;
  }

  // and we are on amd64
  if (_X86_64_ != SystemArch(M)) {
    //llvm::errs() << __FUNCTION__ << ": Not on amd64\n";
    return false;
  }

  // and the __ImageBase symbol is defined
  if (!archGetImageBase(M)) {
    llvm::errs() << __FUNCTION__ << ": No __ImageBase defined\n";
    return false;
  }

  return true;
}

llvm::Value *doSubtractImageBase(llvm::Value *original,
                                 llvm::BasicBlock *block, int width) {
  llvm::Module *M = block->getParent()->getParent();
  auto &C = M->getContext();
  llvm::Value *ImageBase = archGetImageBase(M);

  llvm::Type *intWidthTy = llvm::Type::getIntNTy(C, width);
  llvm::Type *ptrWidthTy = llvm::PointerType::get(intWidthTy, 0);

  // TODO(artem): Why use `64` below??

  // convert original value pointer to int
  llvm::Value *original_int = new llvm::PtrToIntInst(
      original, llvm::Type::getIntNTy(C, 64), "", block);

  // convert image base pointer to int
  llvm::Value *ImageBase_int = new llvm::PtrToIntInst(
      ImageBase, llvm::Type::getIntNTy(C, 64), "", block);

  // do the subtraction
  llvm::Value *data_v = llvm::BinaryOperator::CreateSub(original_int,
                                                        ImageBase_int, "",
                                                        block);

  // convert back to a pointer
  llvm::Value *data_ptr = new llvm::IntToPtrInst(data_v, ptrWidthTy, "", block);

  return data_ptr;
}

llvm::Value *doSubtractImageBaseInt(llvm::Value *original,
                                    llvm::BasicBlock *block) {
  auto M = block->getParent()->getParent();
  auto ImageBase = archGetImageBase(M);

  // convert image base pointer to int
  auto ImageBase_int = new llvm::PtrToIntInst(
      ImageBase, llvm::Type::getIntNTy(block->getContext(), ArchPointerSize(M)),
      "", block);

  // do the subtraction
  return llvm::BinaryOperator::CreateSub(original, ImageBase_int, "", block);
}
