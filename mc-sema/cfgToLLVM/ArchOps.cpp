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
    ci->setCallingConv(CallingConv::X86_StdCall);
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
    F->setCallingConv(CallingConv::X86_StdCall);
  }
}

llvm::Function *addEntryPointDriver(llvm::Module *M, const std::string &name,
                                    VA entry) {
  //convert the VA into a string name of a function, try and look it up
  std::string s("sub_" + to_string<VA>(entry, hex));
  llvm::Function *F = M->getFunction(s);
  if ( !F) {
    llvm::errs() << "Could not find lifted function " << s
                 << " for entry point " << name;
    return nullptr;
  }

  auto &C = F->getContext();
  auto VoidTy = llvm::Type::getVoidTy(C);
  auto EPTy = llvm::FunctionType::get(VoidTy, false);
  auto EP = llvm::dyn_cast<llvm::Function>(M->getOrInsertFunction(name, EPTy));
  if ( !EP->isDeclaration()) {
    llvm::errs() << "Entry point " << name << " is already implemented";
    return EP;
  }

  EP->setLinkage(llvm::GlobalValue::ExternalLinkage);
  EP->setDoesNotReturn();
  EP->addFnAttr(llvm::Attribute::Naked);

  auto Attach = M->getFunction("__mcsema_attach_call");

  const char *inline_asm = "";
  if (32 == getPointerSize(M)) {
    inline_asm = "pushl $0; "
        "pushl $1; "
        "ret;";
  } else {
    inline_asm = "pushq $0; "
        "pushq $1; "
        "ret;";
  }

  llvm::Type *do_attach_arg_types[] = {F->getType(), Attach->getType()};
  auto do_attach_type = llvm::FunctionType::get(VoidTy, do_attach_arg_types,
                                                false);

  auto do_attach = llvm::InlineAsm::get(do_attach_type, inline_asm,
                                        "i,i,~{dirflag},~{fpsr},~{flags}", /* Constraints */
                                        true, /* hasSideEffects */
                                        false, /* isAlignStack */
                                        llvm::InlineAsm::AD_ATT);

  llvm::Value *attach_args[] = {F, Attach};

  auto B = llvm::BasicBlock::Create(C, "entry", EP);
  auto call_attach = llvm::CallInst::Create(do_attach, attach_args, "", B);
  new llvm::UnreachableInst(C, B);
  return EP;
}

llvm::Function *getExitPointDriver(llvm::Function *F) {
  std::stringstream ss;
  ss << "__mcsema_call_" << F->getName().str();
  auto M = F->getParent();
  auto &C = M->getContext();

  auto VoidTy = llvm::Type::getVoidTy(C);
  auto FTy = F->getFunctionType();
  auto RetTy = FTy->getReturnType();
  auto name = ss.str();
  auto W = M->getFunction(name);
  if (!W) {
    W = llvm::Function::Create(FTy, llvm::GlobalValue::ExternalLinkage, name,
                               M);
    W->addFnAttr(llvm::Attribute::NoInline);
    W->addFnAttr(llvm::Attribute::Naked);

    std::stringstream as;
    as << "  .globl " << F->getName().str() << ";\n";
    as << "  .globl " << name << ";\n";
    as << "  .type " << name << ",@function\n";
    as << name << ":\n";
    as << "  .cfi_startproc;\n";
    as << "  pushq $" << F->getName().str() << ";\n";
    as << "  jmp __mcsema_detach_call;\n";
    as << "0:\n";
    as << "  .size " << name << ",0b-" << name << ";\n";
    as << "  .cfi_endproc;\n";

    M->appendModuleInlineAsm(as.str());
  }
  return W;
#if 0
  //  std::vector<llvm::Type *> WArgTys;
  //  WArgTys.insert(WArgTys.begin(), FTy->param_begin(), FTy->param_end());
  //  auto WTy = llvm::FunctionType::get(RetTy, WArgTys, true);

  if (!W->isDeclaration()) {
    return W;
  }

  W->addFnAttr(llvm::Attribute::NoInline);
  W->addFnAttr(llvm::Attribute::Naked);
  W->addFnAttr(llvm::Attribute::OptimizeNone);
  W->setLinkage(llvm::GlobalValue::ExternalLinkage);

  auto Detach = M->getFunction("__mcsema_detach_call");

  const char *inline_asm = "";
  if (32 == getPointerSize(M)) {
    inline_asm = "pushl $0; "
    "pushl $1; "
    "ret;";
  } else {
    inline_asm = "pushq $0; "
    "pushq $1; "
    "ret;";
  }

  llvm::Type *do_detach_arg_types[] = {
    F->getType(),
    Detach->getType()
  };

  auto do_attach_type = llvm::FunctionType::get(
      VoidTy, do_detach_arg_types, false);

  auto do_detach = llvm::InlineAsm::get(
      do_attach_type,
      inline_asm,
      "i,i,~{dirflag},~{fpsr},~{flags}", /* Constraints */
      true, /* hasSideEffects */
      false, /* isAlignStack */
      llvm::InlineAsm::AD_ATT);

  llvm::Value *attach_args[] = {F, Detach};

  auto B = llvm::BasicBlock::Create(C, "entry", W);
  auto call_detach = llvm::CallInst::Create(do_detach, attach_args, "", B);

  //auto call_orig = llvm::CallInst::Create(F, W->getArgumentList(), "", B);

  if (RetTy->isVoidTy()) {
    llvm::ReturnInst::Create(C, B);
  } else {
    llvm::ReturnInst::Create(C, call_detach, B);
  }

  return W;
#endif
}

llvm::Module *archAddCallbacksToModule(llvm::Module *M) {
  const std::string &triple = M->getTargetTriple();
  if (getSystemOS(M) == llvm::Triple::Linux) {
    return M;
  } else if (getSystemOS(M) == llvm::Triple::MacOSX) {
    return M;
  } else if (getSystemOS(M) == llvm::Triple::Win32) {
    return addWin32CallbacksToModule(M);
  } else {
    TASSERT(false, "Unknown OS in Triple!");
  }
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

