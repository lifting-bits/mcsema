#include <string>
#include <iostream>

#include "llvm/ADT/Triple.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/raw_ostream.h"

#include "TransExcn.h"

#include "win32cb.h"

#include "ArchOps.h"
#include "win32ArchOps.h"
#include "linuxArchOps.h"

#include "../common/to_string.h"
#include "../common/Defaults.h"

using namespace std;
using namespace llvm;

unsigned getSystemArch(llvm::Module *M) {
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

llvm::Triple::OSType getSystemOS(llvm::Module *M) {
  llvm::Triple TT(M->getTargetTriple());
  return TT.getOS();
}

unsigned getPointerSize(llvm::Module *M) {
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

void archSetCallingConv(llvm::Module *M, llvm::CallInst *ci) {
  if (getSystemArch(M) == _X86_64_) {
    if (getSystemOS(M) == llvm::Triple::Win32) {
      ci->setCallingConv(CallingConv::X86_64_Win64);
    } else if (getSystemOS(M) == llvm::Triple::Linux) {
      ci->setCallingConv(CallingConv::X86_64_SysV);
    } else if (getSystemOS(M) == llvm::Triple::MacOSX) {
      ci->setCallingConv(CallingConv::X86_64_SysV);
    } else {
      TASSERT(false, "Unsupported OS");
    }
  } else {
    //TODO(artem): handle StdCall
    if (getSystemOS(M) == llvm::Triple::Linux) {
        ci->setCallingConv(CallingConv::C);
    } else {
      TASSERT(false, "Unsupported OS");
    }
  }
}

void archSetCallingConv(llvm::Module *M, llvm::Function *F) {
  if (getSystemArch(M) == _X86_64_) {
    if (getSystemOS(M) == llvm::Triple::Win32) {
      F->setCallingConv(CallingConv::X86_64_Win64);
    } else if (getSystemOS(M) == llvm::Triple::Linux) {
      F->setCallingConv(CallingConv::X86_64_SysV);
    } else if (getSystemOS(M) == llvm::Triple::MacOSX) {
      F->setCallingConv(CallingConv::X86_64_SysV);
    } else {
      TASSERT(false, "Unsupported OS");
    }
  } else {
    //TODO(artem): handle StdCall
    if (getSystemOS(M) == llvm::Triple::Linux) {
        F->setCallingConv(CallingConv::C);
    } else {
      TASSERT(false, "Unsupported OS");
    }
  }
}


static void AddPushJumpStub(llvm::Module *M, llvm::Function *F,
                            llvm::Function *W, const char *stub_handler) {
  auto stub_name = W->getName().str();
  auto stubbed_func_name = F->getName().str();
  const char *push = 32 == getPointerSize(M) ? "pushl" : "pushq";

  std::stringstream as;
  as << "  .globl " << stubbed_func_name << ";\n";
  as << "  .globl " << stub_name << ";\n";
  as << "  .type " << stub_name << ",@function\n";
  as << stub_name << ":\n";
  as << "  .cfi_startproc;\n";
  as << "  " << push << " $" << stubbed_func_name << ";\n";
  as << "  jmp " << stub_handler << ";\n";
  as << "0:\n";
  as << "  .size " << stub_name << ",0b-" << stub_name << ";\n";
  as << "  .cfi_endproc;\n";

  M->appendModuleInlineAsm(as.str());
}

llvm::Function *addEntryPointDriver(llvm::Module *M, const std::string &name,
                                    VA entry) {
  //convert the VA into a string name of a function, try and look it up
  std::string s("sub_" + to_string<VA>(entry, hex));
  llvm::Function *F = M->getFunction(s);
  if (!F) {
    llvm::errs() << "Could not find lifted function " << s
                 << " for entry point " << name;
    return nullptr;
  }

  auto &C = F->getContext();
  auto W = M->getFunction(name);
  if (!W) {
    auto VoidTy = llvm::Type::getVoidTy(C);
    auto WTy = llvm::FunctionType::get(VoidTy, false);
    W = llvm::Function::Create(
        WTy, llvm::GlobalValue::ExternalLinkage, name, M);

    W->addFnAttr(llvm::Attribute::NoInline);
    W->addFnAttr(llvm::Attribute::Naked);

    if (getSystemArch(M) == _X86_64_) {
        AddPushJumpStub(M, F, W, "__mcsema_attach_call");
    } else {
        if (getSystemOS(M) == llvm::Triple::Linux) {
            AddPushJumpStub(M, F, W, "__mcsema_attach_call_cdecl");
        } else {
          TASSERT(false, "Unsupported OS");
        }
    }
    F->setLinkage(llvm::GlobalValue::ExternalLinkage);

    if (F->doesNotReturn()) {
      W->setDoesNotReturn();
    }
  }
  return W;
}

llvm::Function *getExitPointDriver(llvm::Function *F) {
  std::stringstream ss;
  ss << "_" << F->getName().str();
  auto M = F->getParent();
  auto &C = M->getContext();
  auto name = ss.str();
  auto W = M->getFunction(name);
  if (!W) {
    W = llvm::Function::Create(
        F->getFunctionType(), llvm::GlobalValue::ExternalLinkage, name, M);
    W->setCallingConv(F->getCallingConv());
    W->addFnAttr(llvm::Attribute::NoInline);
    W->addFnAttr(llvm::Attribute::Naked);
    if (getSystemArch(M) == _X86_64_) {
        if (getSystemOS(M) == llvm::Triple::Linux) {
            // only one calling conv for linux amd64
            AddPushJumpStub(M, F, W, "__mcsema_detach_call");
        } else {
          TASSERT(false, "Unsupported OS");
        }
    } else {
        if (getSystemOS(M) == llvm::Triple::Linux) {
            switch(F->getCallingConv()) {
                case CallingConv::C:
                    AddPushJumpStub(M, F, W, "__mcsema_detach_call_cdecl");
                    break;
                case CallingConv::X86_StdCall:
                    AddPushJumpStub(M, F, W, "__mcsema_detach_call_stdcall");
                    break;
                case CallingConv::X86_FastCall:
                    AddPushJumpStub(M, F, W, "__mcsema_detach_call_fastcall");
                    break;
                default:
                  TASSERT(false, "Unsupported OS and Calling Convention combination");
            }
        } else {
          TASSERT(false, "Unsupported OS");
        }
    }
    F->setLinkage(llvm::GlobalValue::ExternalLinkage);

    if (F->doesNotReturn()) {
      W->setDoesNotReturn();
    }
  }
  return W;
}


llvm::Function *archMakeCallbackForLocalFunction(Module *M, VA local_target) {
  std::stringstream ss;
  ss << "callback_sub_" << std::hex << local_target;
  auto callback_name = ss.str();
  return addEntryPointDriver(M, callback_name, local_target);
}

GlobalVariable *archGetImageBase(Module *M) {

  // WILL ONLY WORK FOR windows/x86_64
  GlobalVariable *gv = M->getNamedGlobal("__ImageBase");
  return gv;

}

bool shouldSubtractImageBase(Module *M) {

  // we are on windows
  if (getSystemOS(M) != Triple::Win32) {
    //llvm::errs() << __FUNCTION__ << ": Not on Win32\n";
    return false;
  }

  // and we are on amd64
  if (getSystemArch(M) != _X86_64_) {
    //llvm::errs() << __FUNCTION__ << ": Not on amd64\n";
    return false;
  }

  // and the __ImageBase symbol is defined
  if (archGetImageBase(M) == nullptr) {
    llvm::errs() << __FUNCTION__ << ": No __ImageBase defined\n";
    return false;
  }

  return true;

}

llvm::Value* doSubtractImageBaseInt(llvm::Value *original,
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

