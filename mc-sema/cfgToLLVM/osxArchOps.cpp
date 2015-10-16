#include <vector>
#include <string>
#include <iostream>


#include "llvm/IR/Module.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"

#include "raiseX86.h"
#include "X86.h"

#include "../common/to_string.h"
#include "../common/Defaults.h"

extern llvm::PointerType *g_PRegStruct;

using namespace llvm;
using namespace std;

static CallingConv::ID getCallingConv(Module *M){
	if(getSystemArch(M) == _X86_){
		return CallingConv::C;
	} else {
		return CallingConv::X86_64_SysV;
	}
}

static bool osxAddTypesToModule(Module *M) {
    Module *mod = M;

    unsigned int regWidth = getPointerSize(M);

    StructType *StructTy_struct_rlimit = mod->getTypeByName("struct.rlimit");
    if (!StructTy_struct_rlimit) {
        StructTy_struct_rlimit = StructType::create(mod->getContext(), "struct.rlimit");
    }
    std::vector<Type*>StructTy_struct_rlimit_fields;
    StructTy_struct_rlimit_fields.push_back(IntegerType::get(mod->getContext(), regWidth));
    StructTy_struct_rlimit_fields.push_back(IntegerType::get(mod->getContext(), regWidth));
    if (StructTy_struct_rlimit->isOpaque()) {
        StructTy_struct_rlimit->setBody(StructTy_struct_rlimit_fields, /*isPacked=*/false);
    }

    std::vector<Type*>FuncTy_6_args;
    FuncTy_6_args.push_back(IntegerType::get(mod->getContext(), 32));
    FuncTy_6_args.push_back(IntegerType::get(mod->getContext(), regWidth));
    FunctionType* FuncTy_6 = FunctionType::get(
            /*Result=*/IntegerType::get(mod->getContext(), regWidth),
            /*Params=*/FuncTy_6_args,
            /*isVarArg=*/false);

    Function* func_getrlimit = mod->getFunction("getrlimit");
    if (!func_getrlimit) {
        func_getrlimit = Function::Create(
                /*Type=*/FuncTy_6,
                /*Linkage=*/GlobalValue::ExternalLinkage,
                /*Name=*/"getrlimit", mod); // (external, no body)
        func_getrlimit->setCallingConv(getCallingConv(M));
    }

    std::vector<Type*>FuncTy_11_args;
    FuncTy_11_args.push_back(IntegerType::get(mod->getContext(), regWidth));
    FuncTy_11_args.push_back(IntegerType::get(mod->getContext(), regWidth));
    FuncTy_11_args.push_back(IntegerType::get(mod->getContext(), 32));
    FuncTy_11_args.push_back(IntegerType::get(mod->getContext(), 32));
    FuncTy_11_args.push_back(IntegerType::get(mod->getContext(), 32));
    FuncTy_11_args.push_back(IntegerType::get(mod->getContext(), 32));
    FunctionType* FuncTy_11 = FunctionType::get(
            /*Result=*/IntegerType::get(mod->getContext(), regWidth),
            /*Params=*/FuncTy_11_args,
            /*isVarArg=*/false);

    Function* func_mmap = mod->getFunction("mmap");
    if (!func_mmap) {
        func_mmap = Function::Create(
                /*Type=*/FuncTy_11,
                /*Linkage=*/GlobalValue::ExternalLinkage,
                /*Name=*/"mmap", mod); // (external, no body)
        func_mmap->setCallingConv(getCallingConv(M));
    }

    std::vector<Type*>FuncTy_15_args;
    FuncTy_15_args.push_back(IntegerType::get(mod->getContext(), regWidth));
    FuncTy_15_args.push_back(IntegerType::get(mod->getContext(), regWidth));
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
        func_munmap->setCallingConv(getCallingConv(M));
    }

    return true;
}

Value *osxGetStackSize(Module *M, BasicBlock *&driverBB) {

    osxAddTypesToModule(M);

    Module *mod = M;

    unsigned int regWidth = getPointerSize(mod);

    BasicBlock *label_16 = driverBB;
    StructType *StructTy_struct_rlimit = mod->getTypeByName("struct.rlimit");
    PointerType* PointerTy_2 = PointerType::get(IntegerType::get(mod->getContext(), regWidth), 0);

    if(!StructTy_struct_rlimit ) {
        return NULL;
    }

    Function* func_getrlimit = mod->getFunction("getrlimit");

    if(!func_getrlimit) {
        return  NULL;
    }

    AllocaInst* ptr_rl = new AllocaInst(StructTy_struct_rlimit, "rl", label_16);
    CastInst* ptr_17 = new BitCastInst(ptr_rl, PointerTy_2, "", label_16);
    StoreInst* void_18 = new StoreInst(CONST_V(label_16, regWidth, 0), ptr_17, false, label_16);

    std::vector<Value*> int32_19_params;
    int32_19_params.push_back(CONST_V<32>(label_16, 3));
    Value* intized_ptr = new PtrToIntInst(ptr_rl, IntegerType::get(mod->getContext(), regWidth), "", label_16);
    int32_19_params.push_back(intized_ptr);
    CallInst* int32_19 = CallInst::Create(func_getrlimit, int32_19_params, "", label_16);
    int32_19->setCallingConv(getCallingConv(M)/*CallingConv::C*/);
    int32_19->setTailCall(false);

    std::vector<Value*> ptr_20_indices;


    ptr_20_indices.push_back(CONST_V(label_16, regWidth, 0));
    ptr_20_indices.push_back(CONST_V<32>(label_16, 0));

    Instruction* ptr_20 = GetElementPtrInst::Create(ptr_rl, ptr_20_indices, "", label_16);
    LoadInst* int32_21 = new LoadInst(ptr_20, "", false, label_16);
    return int32_21;
}

Value* osxAllocateStack(Module *M, Value *stackSize, BasicBlock *&driverBB) {

    // call mmap(null, stackSize, ...) to allocate stack
    osxAddTypesToModule(M);
    Module *mod = M;
    unsigned int regWidth = getPointerSize(mod);

    Function* func_mmap = mod->getFunction("mmap");

    if(!func_mmap) {
        return  NULL;
    }

    std::vector<Value*> ptr_39_params;
    ptr_39_params.push_back(CONST_V(driverBB, regWidth, 0x0));
    ptr_39_params.push_back(stackSize);
    ptr_39_params.push_back(CONST_V<32>(driverBB, 3));
    ptr_39_params.push_back(CONST_V<32>(driverBB, 0x20022));
    ptr_39_params.push_back(CONST_V<32>(driverBB, -1));
    ptr_39_params.push_back(CONST_V<32>(driverBB, 0));
    CallInst* ptr_39 = CallInst::Create(func_mmap, ptr_39_params, "", driverBB);
    ptr_39->setCallingConv(/*CallingConv::C*/getCallingConv(M));

    return ptr_39;
}


Value *osxFreeStack(Module *M, Value *stackAlloc, BasicBlock *&driverBB) {
    Module *mod = M;
    osxAddTypesToModule(M);

    Value *stack_size = osxGetStackSize(M, driverBB);

    Function* func_munmap = mod->getFunction("munmap");

    if(!func_munmap) {
        return  NULL;
    }

    std::vector<Value*> int32_43_params;
    int32_43_params.push_back(stackAlloc);
    int32_43_params.push_back(stack_size);
    CallInst* int32_43 = CallInst::Create(func_munmap, int32_43_params, "", driverBB);
    int32_43->setCallingConv(getCallingConv(M)/*CallingConv::C*/);
    int32_43->setTailCall(true);

    return int32_43;
}

llvm::Value *osxMakeCallbackForLocalFunction(Module *M , VA local_target) {
    std::string			call_tgt_name = "sub_" + to_string<VA>(local_target, std::hex);

    Function        *call_tgt = M->getFunction(call_tgt_name);
    TASSERT(call_tgt != NULL, "Cannot find call target function in callback stub: "+call_tgt_name);

    std::cout << "!!!WARNING WARNING WARNING!!!" << "\n";
    std::cout << "\tAssuming all callbacks are to translated code!!!\n";

    return call_tgt;
}

void osxAddCallValue(Module *M) {
    std::vector<Type*>FuncCallValueTy_args;
    unsigned int regWidth = getPointerSize(M);

    Type *intType = IntegerType::get(M->getContext(), regWidth);
    PointerType* intType_ptr = PointerType::get(intType, 0);

    FuncCallValueTy_args.push_back(g_PRegStruct);
    FuncCallValueTy_args.push_back(intType);

    FunctionType* FuncCallValueTy = FunctionType::get(
            /*Result=*/Type::getVoidTy(M->getContext()),
            /*Params=*/FuncCallValueTy_args,
            /*isVarArg=*/false);

    vector<Type *>  xlated_func_args;
    xlated_func_args.push_back(g_PRegStruct);
    Type  *xlated_func_returnTy = Type::getVoidTy(M->getContext());
    FunctionType *xlatedFuncTy = FunctionType::get(xlated_func_returnTy, xlated_func_args, false);

    PointerType* xlatedFuncPtrTy = PointerType::get(xlatedFuncTy, 0);

    // if do_call_value has not already been added to this module,
    // then create it
    Function* func_do_call_value = M->getFunction("do_call_value");
    if (!func_do_call_value) {
        func_do_call_value = Function::Create(
                /*Type=*/FuncCallValueTy,
                /*Linkage=*/GlobalValue::InternalLinkage,
                /*Name=*/"do_call_value", M); 
        func_do_call_value->setCallingConv(CallingConv::C);
        func_do_call_value->addFnAttr(Attribute::AlwaysInline);
    }

    // Function Definitions
    // Function: do_call_value (func_do_call_value)
    {
        // get pointers to the two function arguments.
        // the first argument is a pointer to the global
        // struct.regs instance
        // the second is a pointer to the function that we will be calling
        Function::arg_iterator args = func_do_call_value->arg_begin();
        Value* arg0 = args++;
        arg0->setName("reg_context");
        Value* arg1 = args++;
        arg1->setName("ptr");


        BasicBlock* main_block = BasicBlock::Create(M->getContext(), "", func_do_call_value, 0);

        // ASSUME TARGET FUNCTION IS TRANSLATED CODE
        // JUST CALL target_function(context)
        // ASSUME TARGET FUNCTION IS TRANSLATED CODE
        //
        Value *target_fn = new llvm::IntToPtrInst(arg1, xlatedFuncPtrTy, "", main_block);

        vector<Value*> context_arg;
        context_arg.push_back(arg0);
        CallInst* ignored_value = CallInst::Create(target_fn, context_arg, "", main_block);
        ignored_value->setCallingConv(getCallingConv(M)/*CallingConv::X86_StdCall*/);
        ReturnInst::Create(M->getContext(), main_block);
    }
}
