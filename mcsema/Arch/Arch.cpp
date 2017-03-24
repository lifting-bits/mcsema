/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <unordered_set>

#include <llvm/ADT/ArrayRef.h>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/Dispatch.h"

namespace {

static std::string gDataLayout;
static std::string gTriple;

static int gAddressSize = 0;

static llvm::CallingConv::ID gCallingConv;
static llvm::Triple::ArchType gArchType;
static llvm::Triple::OSType gOSType;

}  // namespace

bool InitArch(llvm::LLVMContext *context, const std::string &os,
              const std::string &arch) {

  LOG(INFO)
      << "Initializing for " << arch << " code on " << os;

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

  return true;
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
    LOG(FATAL)
        << "Unsupported triple";
  }
}

static void InitADFeatues(llvm::Module *M, const char *name,
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
      InitADFeatues(M, "__mcsema_attach_call", EPTy);
      InitADFeatues(M, "__mcsema_attach_ret", EPTy);
      InitADFeatues(M, "__mcsema_detach_call", EPTy);
      InitADFeatues(M, "__mcsema_detach_call_value", EPTy);
      InitADFeatues(M, "__mcsema_detach_ret", EPTy);

    } else {
      InitADFeatues(M, "__mcsema_attach_call_cdecl", EPTy);
      InitADFeatues(M, "__mcsema_attach_ret_cdecl", EPTy);
      InitADFeatues(M, "__mcsema_detach_call_cdecl", EPTy);
      InitADFeatues(M, "__mcsema_detach_ret_cdecl", EPTy);
      InitADFeatues(M, "__mcsema_detach_call_value", EPTy);
      InitADFeatues(M, "__mcsema_attach_ret_value", EPTy);

      InitADFeatues(M, "__mcsema_detach_call_stdcall", EPTy);
      InitADFeatues(M, "__mcsema_attach_ret_stdcall", EPTy);
      InitADFeatues(M, "__mcsema_detach_call_fastcall", EPTy);
      InitADFeatues(M, "__mcsema_attach_ret_fastcall", EPTy);
    }
  } else if (llvm::Triple::Win32 == OS) {
    if (_X86_64_ == Arch) {
      InitADFeatues(M, "__mcsema_attach_call", EPTy);
      InitADFeatues(M, "__mcsema_attach_ret", EPTy);
      InitADFeatues(M, "__mcsema_detach_call", EPTy);
      InitADFeatues(M, "__mcsema_detach_call_value", EPTy);
      InitADFeatues(M, "__mcsema_detach_ret", EPTy);
    } else {
      InitADFeatues(M, "__mcsema_attach_call_cdecl", EPTy);
      InitADFeatues(M, "__mcsema_attach_ret_cdecl", EPTy);
      InitADFeatues(M, "__mcsema_detach_call_cdecl", EPTy);
      InitADFeatues(M, "__mcsema_detach_ret_cdecl", EPTy);
      InitADFeatues(M, "__mcsema_detach_call_value", EPTy);
      InitADFeatues(M, "__mcsema_attach_ret_value", EPTy);

      InitADFeatues(M, "__mcsema_detach_call_stdcall", EPTy);
      InitADFeatues(M, "__mcsema_attach_ret_stdcall", EPTy);
      InitADFeatues(M, "__mcsema_detach_call_fastcall", EPTy);
      InitADFeatues(M, "__mcsema_attach_ret_fastcall", EPTy);
    }
  } else {
    LOG(FATAL)
        << "Unknown OS Type!";
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
  if (64 == ArchAddressSize()) {
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
      LOG(FATAL)
          << "Unsupported Calling Convention for 32-bit Windows";
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

  if (decorateStub) {
    stub_name = WindowsDecorateName(W, stub_name);
  }

  as << "  .globl " << stubbed_func_name << ";\n";
  as << "  .globl " << stub_name << ";\n";
  as << stub_name << ":\n";
  as << "  .cfi_startproc;\n";
  if (32 == ArchPointerSize(M)) {
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
  // convert the VA into a string name of a function, try and look it up
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
    LOG(FATAL)
        << "Unsupported OS for entry point driver.";
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

  if (llvm::Triple::Win32 == OS) {
      ss << "mcsema_" << F->getName().str();
  } else {
      ss << "_" << F->getName().str();
  }

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
          LOG(FATAL)
              << "Unsupported Calling Convention for 32-bit Linux";
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
          WindowsAddPushJumpStub(true, M, F, W,
                                 "__mcsema_detach_call_fastcall");
          break;
        default:
          LOG(FATAL)
              << "Unsupported Calling Convention for 32-bit Windows";
          break;
      }
    }
  } else {
    LOG(FATAL)
        << "Unsupported OS for exit point driver.";
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
    return false;
  }

  // and we are on amd64
  if (_X86_64_ != SystemArch(M)) {
    return false;
  }

  // and the __ImageBase symbol is defined
  if (!archGetImageBase(M)) {
    LOG(WARNING)
        << "No __ImageBase defined";
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
