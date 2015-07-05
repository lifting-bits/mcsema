#include <string>
#include <iostream>

#include "TransExcn.h"

#include "win32cb.h"

#include "ArchOps.h"
#include "win32ArchOps.h"
#include "linuxArchOps.h"

#include "../common/to_string.h"
#include "../common/Defaults.h"
#include "llvm/ADT/Triple.h"

using namespace std;
using namespace llvm;

unsigned getSystemArch(llvm::Module *M) {
    llvm::Triple TT(M->getTargetTriple());
    llvm::Triple::ArchType arch = TT.getArch();
    if(arch == llvm::Triple::x86) {
        return _X86_;
    } else if(arch == llvm::Triple::x86_64) {
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
    if(arch == llvm::Triple::x86) {
        return Pointer32;
    } else if(arch == llvm::Triple::x86_64) {
        return Pointer64;
    } else {
        throw TErr(__LINE__, __FILE__, "Unsupported architecture");
    }
}

void archSetCallingConv(llvm::Module *M, llvm::CallInst *ci) {
    if(getSystemArch(M) ==  _X86_64_ ) {
        if( getSystemOS(M) == llvm::Triple::Win32 ) {
            ci->setCallingConv(CallingConv::X86_64_Win64);
        } else if (getSystemOS(M) == llvm::Triple::Linux ) {
            ci->setCallingConv(CallingConv::X86_64_SysV);
        } else {
            TASSERT(false, "Unsupported OS");
        }
    } else {
        ci->setCallingConv(CallingConv::X86_StdCall);
    }
}

void archSetCallingConv(llvm::Module *M, llvm::Function *F) {
    if(getSystemArch(M) ==  _X86_64_ ) {
        if( getSystemOS(M) == llvm::Triple::Win32 ) {
            F->setCallingConv(CallingConv::X86_64_Win64);
        } else if (getSystemOS(M) == llvm::Triple::Linux ) {
            F->setCallingConv(CallingConv::X86_64_SysV);
        } else {
            TASSERT(false, "Unsupported OS");
        }
    } else {
        F->setCallingConv(CallingConv::X86_StdCall);
    }
}

Value* archAllocateStack(Module *M, Value *stackSize, BasicBlock *&driverBB) {
    // VirtualAlloc a stack buffer the same size as the current thread's
    // stack size
    
    const std::string &triple = M->getTargetTriple();
    Value *stackAlloc = NULL;

    if( getSystemOS(M) == llvm::Triple::Linux ) {
        stackAlloc = linuxAllocateStack(M, stackSize, driverBB);
    } else if(getSystemOS(M) == llvm::Triple::Win32) {
        stackAlloc = win32AllocateStack(M, stackSize, driverBB);
    } else { 
        cout << "WARNING: Unknown OS: " << getSystemOS(M) << "\n";
        cout << "WARNING: Unknown architecture triple: " << triple << "\n";
        cout << "Assuming Win32 semantics\n";
        stackAlloc = win32AllocateStack(M, stackSize, driverBB);
    }

    TASSERT(stackAlloc != NULL, "Could not allocate stack!");
    return stackAlloc;
}


Value *archFreeStack(Module *M, Value *stackAlloc, BasicBlock *&driverBB) {

    const std::string &triple = M->getTargetTriple();
    Value *stackFree = NULL;

    if(triple == LINUX_TRIPLE || triple == LINUX_TRIPLE_X64) {
        stackFree = linuxFreeStack(M, stackAlloc, driverBB);
    } else if(triple == WINDOWS_TRIPLE || triple == WINDOWS_TRIPLE_X64) {
        // free our allocated stack
        stackFree = win32FreeStack(stackAlloc, driverBB);
    } else { 
        stackFree = win32FreeStack(stackAlloc, driverBB);
    }

    TASSERT(stackFree != NULL, "Could not free stack!");
    return stackFree;
}

Module* archAddCallbacksToModule(Module *M) {
    const std::string &triple = M->getTargetTriple();
    if(triple == LINUX_TRIPLE || triple == LINUX_TRIPLE_X64) {
        return M;
    } else if(triple == WINDOWS_TRIPLE || triple == WINDOWS_TRIPLE_X64) {
        return addWin32CallbacksToModule(M);
    } else { 
        return addWin32CallbacksToModule(M);
    }
}

llvm::Value *archMakeCallbackForLocalFunction(Module *M, VA local_target)
{

    const std::string &triple = M->getTargetTriple();
    if(triple == LINUX_TRIPLE || triple == LINUX_TRIPLE_X64) {
        return linuxMakeCallbackForLocalFunction(M, local_target);
    } else if(triple == WINDOWS_TRIPLE || triple == WINDOWS_TRIPLE_X64) {
        return win32MakeCallbackForLocalFunction(M, local_target);
    } else { 
        return win32MakeCallbackForLocalFunction(M, local_target);
    }

}

void archAddCallValue(Module *M) {
    const std::string &triple = M->getTargetTriple();

    if(triple == LINUX_TRIPLE || triple == LINUX_TRIPLE_X64) {
        return linuxAddCallValue(M);
    } else if(triple == WINDOWS_TRIPLE || triple == WINDOWS_TRIPLE_X64) {
        // free our allocated stack
        return win32AddCallValue(M);
    } else { 
        return win32AddCallValue(M);
    }
}

Value* archGetStackSize(Module *M, BasicBlock *&driverBB) {
    const std::string &triple = M->getTargetTriple();
    Value *stackSize = NULL;

    if( getSystemOS(M) == llvm::Triple::Linux ) {
        stackSize = linuxGetStackSize(M, driverBB);
    } else if(getSystemOS(M) == llvm::Triple::Win32) {
        stackSize = win32GetStackSize(M, driverBB);
    } else { 
        cout << "WARNING: Unknown OS: " << getSystemOS(M) << "\n";
        cout << "WARNING: Unknown architecture triple: " << triple << "\n";
        cout << "Assuming Win32 semantics\n";
        stackSize = win32GetStackSize(M, driverBB);
    }

    TASSERT(stackSize != NULL, "Could not allocate stack!");
    return stackSize;
}
