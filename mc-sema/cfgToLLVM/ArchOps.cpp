#include "llvm/Module.h"
#include "llvm/BasicBlock.h"
#include "llvm/Type.h"
#include <string>
#include <iostream>
#include "../common/Defaults.h"
#include "TransExcn.h"
#include "win32cb.h"
#include "llvm/Constants.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Instructions.h"

using namespace std;
using namespace llvm;

template <int width>
static llvm::ConstantInt *CONST_V(llvm::BasicBlock *b, uint64_t val) {
    llvm::IntegerType *bTy = llvm::Type::getIntNTy(b->getContext(), width);
    return llvm::ConstantInt::get(bTy, val);
}

static bool linuxAddTypesToModule(Module *M) {
    Module *mod = M;

    StructType *StructTy_struct_rlimit = mod->getTypeByName("struct.rlimit");
    if (!StructTy_struct_rlimit) {
        StructTy_struct_rlimit = StructType::create(mod->getContext(), "struct.rlimit");
    }
    std::vector<Type*>StructTy_struct_rlimit_fields;
    StructTy_struct_rlimit_fields.push_back(IntegerType::get(mod->getContext(), 32));
    StructTy_struct_rlimit_fields.push_back(IntegerType::get(mod->getContext(), 32));
    if (StructTy_struct_rlimit->isOpaque()) {
        StructTy_struct_rlimit->setBody(StructTy_struct_rlimit_fields, /*isPacked=*/false);
    }

    PointerType* PointerTy_3 = PointerType::get(StructTy_struct_rlimit, 0);

    std::vector<Type*>FuncTy_6_args;
    FuncTy_6_args.push_back(IntegerType::get(mod->getContext(), 32));
    FuncTy_6_args.push_back(PointerTy_3);
    FunctionType* FuncTy_6 = FunctionType::get(
            /*Result=*/IntegerType::get(mod->getContext(), 32),
            /*Params=*/FuncTy_6_args,
            /*isVarArg=*/false);

    Function* func_getrlimit = mod->getFunction("getrlimit");
    if (!func_getrlimit) {
        func_getrlimit = Function::Create(
                /*Type=*/FuncTy_6,
                /*Linkage=*/GlobalValue::ExternalLinkage,
                /*Name=*/"getrlimit", mod); // (external, no body)
        func_getrlimit->setCallingConv(CallingConv::C);
    }

    PointerType* PointerTy_8 = PointerType::get(IntegerType::get(mod->getContext(), 8), 0);
    std::vector<Type*>FuncTy_11_args;
    FuncTy_11_args.push_back(PointerTy_8);
    FuncTy_11_args.push_back(IntegerType::get(mod->getContext(), 32));
    FuncTy_11_args.push_back(IntegerType::get(mod->getContext(), 32));
    FuncTy_11_args.push_back(IntegerType::get(mod->getContext(), 32));
    FuncTy_11_args.push_back(IntegerType::get(mod->getContext(), 32));
    FuncTy_11_args.push_back(IntegerType::get(mod->getContext(), 32));
    FunctionType* FuncTy_11 = FunctionType::get(
            /*Result=*/PointerTy_8,
            /*Params=*/FuncTy_11_args,
            /*isVarArg=*/false);

    Function* func_mmap = mod->getFunction("mmap");
    if (!func_mmap) {
        func_mmap = Function::Create(
                /*Type=*/FuncTy_11,
                /*Linkage=*/GlobalValue::ExternalLinkage,
                /*Name=*/"mmap", mod); // (external, no body)
        func_mmap->setCallingConv(CallingConv::C);
    }

    std::vector<Type*>FuncTy_15_args;
    FuncTy_15_args.push_back(PointerTy_8);
    FuncTy_15_args.push_back(IntegerType::get(mod->getContext(), 32));
    FunctionType* FuncTy_15 = FunctionType::get(
            /*Result=*/IntegerType::get(mod->getContext(), 32),
            /*Params=*/FuncTy_15_args,
            /*isVarArg=*/false);
    Function* func_munmap = mod->getFunction("munmap");
    if (!func_munmap) {
        func_munmap = Function::Create(
                /*Type=*/FuncTy_15,
                /*Linkage=*/GlobalValue::ExternalLinkage,
                /*Name=*/"munmap", mod); // (external, no body)
        func_munmap->setCallingConv(CallingConv::C);
    }

    return true;
}

static Value *linuxGetStackSize(Module *M, BasicBlock *&driverBB) {

    linuxAddTypesToModule(M);

    Module *mod = M;

    BasicBlock *label_16 = driverBB;
    StructType *StructTy_struct_rlimit = mod->getTypeByName("struct.rlimit");
    PointerType* PointerTy_2 = PointerType::get(IntegerType::get(mod->getContext(), 64), 0);

    if(!StructTy_struct_rlimit ) {
        return NULL;
    }

    Function* func_getrlimit = mod->getFunction("getrlimit");

    if(!func_getrlimit) {
        return  NULL;
    }

    AllocaInst* ptr_rl = new AllocaInst(StructTy_struct_rlimit, "rl", label_16);
    CastInst* ptr_17 = new BitCastInst(ptr_rl, PointerTy_2, "", label_16);
    StoreInst* void_18 = new StoreInst(CONST_V<64>(label_16, 0), ptr_17, false, label_16);
    std::vector<Value*> int32_19_params;
    int32_19_params.push_back(CONST_V<32>(label_16, 3));
    int32_19_params.push_back(ptr_rl);
    CallInst* int32_19 = CallInst::Create(func_getrlimit, int32_19_params, "", label_16);
    int32_19->setCallingConv(CallingConv::C);
    int32_19->setTailCall(false);

    std::vector<Value*> ptr_20_indices;
    ptr_20_indices.push_back(CONST_V<32>(label_16, 0));
    ptr_20_indices.push_back(CONST_V<32>(label_16, 0));

    Instruction* ptr_20 = GetElementPtrInst::Create(ptr_rl, ptr_20_indices, "", label_16);
    LoadInst* int32_21 = new LoadInst(ptr_20, "", false, label_16);
    return int32_21;
}

static Value* linuxAllocateStack(Module *M, Value *stackSize, BasicBlock *&driverBB) {

    // call mmap(null, stackSize, ...) to allocate stack
    linuxAddTypesToModule(M);
    Module *mod = M;

    Function* func_mmap = mod->getFunction("mmap");

    if(!func_mmap) {
        return  NULL;
    }

    PointerType* PointerTy_8 = PointerType::get(IntegerType::get(mod->getContext(), 8), 0);
    ConstantPointerNull* null_ptr = ConstantPointerNull::get(PointerTy_8);

    std::vector<Value*> ptr_39_params;
    ptr_39_params.push_back(null_ptr);
    ptr_39_params.push_back(stackSize);
    ptr_39_params.push_back(CONST_V<32>(driverBB, 3));
    ptr_39_params.push_back(CONST_V<32>(driverBB, 0x20022));
    ptr_39_params.push_back(CONST_V<32>(driverBB, -1));
    ptr_39_params.push_back(CONST_V<32>(driverBB, 0));
    CallInst* ptr_39 = CallInst::Create(func_mmap, ptr_39_params, "", driverBB);
    ptr_39->setCallingConv(CallingConv::C);

    CastInst* stackPtrInt = new PtrToIntInst(ptr_39, IntegerType::get(mod->getContext(), 32), "", driverBB);

    return stackPtrInt;
}

static Value* win32GetStackSize(Module *M, BasicBlock *&driverBB) {
    Value *pTEB = win32GetTib(driverBB);
    Value *stackSize = win32GetStackSize(pTEB, driverBB);
    return stackSize;
}

static Value* win32AllocateStack(Module *M, Value *stackSize, BasicBlock *&driverBB) {
    Value *aStack = win32CallVirtualAlloc(stackSize, driverBB);
    return aStack;
}

Value* archGetStackSize(Module *M, BasicBlock *&driverBB) {
    const std::string &triple = M->getTargetTriple();
    Value *stackSize = NULL;

    if(triple == LINUX_TRIPLE) {
        stackSize = linuxGetStackSize(M, driverBB);
    } else if(triple == WINDOWS_TRIPLE) {
        stackSize = win32GetStackSize(M, driverBB);
    } else { 
        cout << "WARNING: Unknown architecture triple: " << triple << "\n";
        cout << "Assuming Win32 semantics\n";
        stackSize = win32GetStackSize(M, driverBB);
    }

    TASSERT(stackSize != NULL, "Could not allocate stack!");
    return stackSize;
}

Value* archAllocateStack(Module *M, Value *stackSize, BasicBlock *&driverBB) {
    // VirtualAlloc a stack buffer the same size as the current thread's
    // stack size
    
    const std::string &triple = M->getTargetTriple();
    Value *stackAlloc = NULL;

    if(triple == LINUX_TRIPLE) {
        stackAlloc = linuxAllocateStack(M, stackSize, driverBB);
    } else if(triple == WINDOWS_TRIPLE) {
        stackAlloc = win32AllocateStack(M, stackSize, driverBB);
    } else { 
        cout << "WARNING: Unknown architecture triple: " << triple << "\n";
        cout << "Assuming Win32 semantics\n";
        stackAlloc = win32AllocateStack(M, stackSize, driverBB);
    }

    TASSERT(stackAlloc != NULL, "Could not allocate stack!");
    return stackAlloc;
}

static Value *linuxFreeStack(Module *M, Value *stackAlloc, BasicBlock *&driverBB) {
    Module *mod = M;
    linuxAddTypesToModule(M);

    Value *stack_size = linuxGetStackSize(M, driverBB);

    PointerType* PointerTy_8 = PointerType::get(IntegerType::get(mod->getContext(), 8), 0);

    Function* func_munmap = mod->getFunction("munmap");

    if(!func_munmap) {
        return  NULL;
    }

    Value *stackPtr = new IntToPtrInst(stackAlloc, PointerTy_8, "", driverBB);

    std::vector<Value*> int32_43_params;
    int32_43_params.push_back(stackPtr);
    int32_43_params.push_back(stack_size);
    CallInst* int32_43 = CallInst::Create(func_munmap, int32_43_params, "", driverBB);
    int32_43->setCallingConv(CallingConv::C);
    int32_43->setTailCall(true);

    return int32_43;
}

static Value *win32FreeStack(Value *stackAlloc, BasicBlock *&driverBB) {
    Value *freeIt = win32CallVirtualFree(stackAlloc, driverBB);
    return freeIt;
}

Value *archFreeStack(Module *M, Value *stackAlloc, BasicBlock *&driverBB) {

    const std::string &triple = M->getTargetTriple();
    Value *stackFree = NULL;

    if(triple == LINUX_TRIPLE) {
        stackFree = linuxFreeStack(M, stackAlloc, driverBB);
    } else if(triple == WINDOWS_TRIPLE) {
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
    if(triple == LINUX_TRIPLE) {
        return M;
    } else if(triple == WINDOWS_TRIPLE) {
        return addWin32CallbacksToModule(M);
    } else { 
        return addWin32CallbacksToModule(M);
    }
}

