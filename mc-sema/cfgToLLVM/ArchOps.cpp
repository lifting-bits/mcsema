
#include <string>
#include <sstream>

#include "llvm/ADT/Triple.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/raw_ostream.h"

#include "TransExcn.h"

#include "ArchOps.h"

#include "../common/Defaults.h"

using namespace std;
using namespace llvm;

SystemArchType SystemArch(llvm::Module *M) {
  llvm::Triple TT(M->getTargetTriple());
  llvm::Triple::ArchType arch = TT.getArch();
  if (arch == llvm::Triple::x86) {
    return _X86_;
  } else if (arch == llvm::Triple::x86_64) {
    return _X86_64_;
  } else {
    throw TErr(__LINE__, __FILE__, "Unsupported architecture");
  }
}

llvm::Triple::OSType SystemOS(llvm::Module *M) {
  llvm::Triple TT(M->getTargetTriple());
  return TT.getOS();
}

PointerSize ArchPointerSize(llvm::Module *M) {
  llvm::Triple TT(M->getTargetTriple());
  llvm::Triple::ArchType arch = TT.getArch();
  if (arch == llvm::Triple::x86) {
    return Pointer32;
  } else if (arch == llvm::Triple::x86_64) {
    return Pointer64;
  } else {
    throw TErr(__LINE__, __FILE__, "Unsupported architecture");
  }
}

llvm::CallingConv::ID ArchGetCallingConv(llvm::Module *M) {
  const auto OS = SystemOS(M);
  const auto Arch = SystemArch(M);
  if (llvm::Triple::Win32 == OS) {
    if (_X86_64_ == Arch) {
      return CallingConv::X86_64_Win64;
    } else {
      return CallingConv::C;
    }
  } else if (llvm::Triple::Linux == OS) {
    if (_X86_64_ == Arch) {
      return CallingConv::X86_64_SysV;
    } else {
      return CallingConv::C;
    }
  } else {
    TASSERT(false, "Unsupported OS");
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

std::string ArchNameMcsemaCall(const std::string &name) {
    return "__mcsema_" + name;
}


static std::string WindowsDecorateName(llvm::Function *F, const std::string &name) {

  // 64-bit doesn't mangle
    Module *M = F->getParent();
    if(64 == ArchPointerSize(M)) {
      return name;
    }

    switch(F->getCallingConv())
    {

        case CallingConv::C:
          return "_" + name;
          break;
        case CallingConv::X86_StdCall:
          {
            std::stringstream as;
            int argc = F->arg_size();
            as << "_" << name << "@" << argc*4;
            return as.str();
          }
          break;
        case CallingConv::X86_FastCall:
          {
            std::stringstream as;
            int argc = F->arg_size();
            as << "@" << name << "@" << argc*4;
            return as.str();
          }
          break;
        default:
          TASSERT(false, "Unsupported Calling Convention for 32-bit Windows");
          break;
      }
      return "";
}
static void WindowsAddPushJumpStub(bool decorateStub, llvm::Module *M, llvm::Function *F,
                                 llvm::Function *W, const char *stub_handler) {
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
                             llvm::GlobalValue::ExternalLinkage, name, M);
  W->setCallingConv(F->getCallingConv());
  W->addFnAttr(llvm::Attribute::NoInline);
  W->addFnAttr(llvm::Attribute::Naked);

  const auto Arch = SystemArch(M);

  if (llvm::Triple::Linux == OS) {
    if (_X86_64_ == Arch) {
      LinuxAddPushJumpStub(M, F, W, "__mcsema_detach_call");
    } else {
      switch (F->getCallingConv()) {
        case CallingConv::C:
          LinuxAddPushJumpStub(M, F, W, "__mcsema_detach_call_cdecl");
          break;
        case CallingConv::X86_StdCall:
          LinuxAddPushJumpStub(M, F, W, "__mcsema_detach_call_stdcall");
          break;
        case CallingConv::X86_FastCall:
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
        case CallingConv::C:
          WindowsAddPushJumpStub(true, M, F, W, "__mcsema_detach_call_cdecl");
          break;
        case CallingConv::X86_StdCall:
          WindowsAddPushJumpStub(true, M, F, W, "__mcsema_detach_call_stdcall");
          break;
        case CallingConv::X86_FastCall:
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

  F->setLinkage(llvm::GlobalValue::ExternalLinkage);  // TODO(artem): No-op?
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

llvm::Value *doSubtractImageBaseInt(llvm::Value *original,
                                    llvm::BasicBlock *block) {
  llvm::Module *M = block->getParent()->getParent();
  llvm::Value *ImageBase = archGetImageBase(M);

  // convert image base pointer to int
  llvm::Value *ImageBase_int = new llvm::PtrToIntInst(
      ImageBase, llvm::Type::getIntNTy(block->getContext(), 64), "", block);

  // do the subtraction
  llvm::Value *data_v = BinaryOperator::CreateSub(original, ImageBase_int, "",
                                                  block);

  return data_v;
}

