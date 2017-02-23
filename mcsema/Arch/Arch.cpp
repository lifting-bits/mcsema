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

// Define the generic arch function pointers.
const std::string &(*ArchRegisterName)(MCSemaRegs) = nullptr;
MCSemaRegs (*ArchRegisterNumber)(const std::string &) = nullptr;
unsigned (*ArchRegisterOffset)(MCSemaRegs) = nullptr;
MCSemaRegs (*ArchRegisterParent)(MCSemaRegs) = nullptr;
void (*ArchAllocRegisterVars)(llvm::BasicBlock *) = nullptr;
unsigned (*ArchRegisterSize)(MCSemaRegs) = nullptr;
llvm::StructType *(*ArchRegStateStructType)(void) = nullptr;

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

