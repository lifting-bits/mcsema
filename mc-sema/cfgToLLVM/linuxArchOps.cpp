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
#include "x86Helpers.h"
#include "X86.h"

#include "../common/to_string.h"
#include "../common/Defaults.h"

static bool added_callbacks = false;

extern llvm::PointerType *g_PRegStruct;

using namespace llvm;
using namespace std;

static Module* linuxAddCallbacksToModule(Module *mod) {

    // add definition for:
    //   1 extern __attribute__((naked)) int __mcsema_inception();
    std::vector<Type*>FuncTy_6_args;
    FunctionType* FuncTy_6 = FunctionType::get(
            /*Result=*/IntegerType::get(mod->getContext(), 32),
            /*Params=*/FuncTy_6_args,
            /*isVarArg=*/false);
    Function* func___mcsema_inception = mod->getFunction("__mcsema_inception");
    if (!func___mcsema_inception) {
        func___mcsema_inception = Function::Create(
                /*Type=*/FuncTy_6,
                /*Linkage=*/GlobalValue::ExternalLinkage,
                /*Name=*/"__mcsema_inception", mod); // (external, no body)
        func___mcsema_inception->setCallingConv(CallingConv::C);
    }
    AttributeSet func___mcsema_inception_PAL;
    {
        SmallVector<AttributeSet, 4> Attrs;
        AttributeSet PAS;
        {
            AttrBuilder B;
            PAS = AttributeSet::get(mod->getContext(), ~0U, B);
        }

        Attrs.push_back(PAS);
        func___mcsema_inception_PAL = AttributeSet::get(mod->getContext(), Attrs);

    }
    func___mcsema_inception->setAttributes(func___mcsema_inception_PAL);

    return mod;
}

static Function *linuxGetInceptionFunction(Module *M) {
    if(!added_callbacks) {
        std::cout << __FUNCTION__ << ": Adding Callbacks to Module!" << std::endl;
        linuxAddCallbacksToModule(M);
        added_callbacks = true;
    }

    return M->getFunction("__mcsema_inception");
}


static CallingConv::ID getCallingConv(Module *M){
	if(getSystemArch(M) == _X86_){
		return CallingConv::C;
	} else {
		return CallingConv::X86_64_SysV;
	}
}

static bool linuxAddTypesToModule(Module *M) {
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

Value *linuxGetStackSize(Module *M, BasicBlock *&driverBB) {

    linuxAddTypesToModule(M);

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

Value* linuxAllocateStack(Module *M, Value *stackSize, BasicBlock *&driverBB) {

    // call mmap(null, stackSize, ...) to allocate stack
    linuxAddTypesToModule(M);
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


Value *linuxFreeStack(Module *M, Value *stackAlloc, BasicBlock *&driverBB) {
    Module *mod = M;
    linuxAddTypesToModule(M);

    Value *stack_size = linuxGetStackSize(M, driverBB);

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

llvm::Value *linuxMakeCallbackForLocalFunction(Module *M , VA local_target) {

    std::string	call_tgt_name = "sub_" + to_string<VA>(local_target, std::hex);
    std::string	callback_name = "callback_sub_" + to_string<VA>(local_target, std::hex);

    Function *call_tgt = M->getFunction(call_tgt_name);
    TASSERT( call_tgt != NULL, "Cannot find target for callback");

    Function *callback = M->getFunction(callback_name);

    // already have a callback
    if(callback != nullptr) {
        return callback;
    }

    unsigned regWidth = getPointerSize(M);

    // no driver, make one
    FunctionType    *callbackTy = 
        FunctionType::get( Type::getIntNTy(M->getContext(), regWidth), false );

    Function *F = dynamic_cast<Function*>(M->getOrInsertFunction(callback_name, callbackTy));
    TASSERT( F != NULL, "Cannot create callback stub" );
    F->setLinkage(GlobalValue::InternalLinkage);
    F->addFnAttr(Attribute::Naked);

    // add code to driver
    BasicBlock *block = BasicBlock::Create(
            F->getContext(), "", F);

    std::vector<Type*>FuncTy_9_args;
    FuncTy_9_args.push_back(call_tgt->getType());
    FunctionType* FuncTy_9 = FunctionType::get(
            /*Result=*/Type::getVoidTy(M->getContext()),
            /*Params=*/FuncTy_9_args,
            /*isVarArg=*/false);

    if(getSystemArch(M) == _X86_64_) {

        InlineAsm* ptr_13 = InlineAsm::get(FuncTy_9, "pushq $0\n", "imr,~{dirflag},~{fpsr},~{flags}",true);
        CallInst* void_12 = CallInst::Create(ptr_13, call_tgt, "", block);
        void_12->setCallingConv(CallingConv::C);
        void_12->setTailCall(false);
    } else {
        InlineAsm* ptr_13 = InlineAsm::get(FuncTy_9, "pushl $0\n", "imr,~{dirflag},~{fpsr},~{flags}",true);
        CallInst* void_12 = CallInst::Create(ptr_13, call_tgt, "", block);
        void_12->setCallingConv(CallingConv::C);
        void_12->setTailCall(false);
    }

    Function *inception = linuxGetInceptionFunction(M);

    std::vector<Type*>call_inception_args;
    call_inception_args.push_back(inception->getType());
    FunctionType* call_inception_ty = FunctionType::get(
            /*Result=*/Type::getVoidTy(M->getContext()),
            /*Params=*/call_inception_args,
            /*isVarArg=*/false);

    if(getSystemArch(M) == _X86_64_) {

        InlineAsm* ptr_15 = InlineAsm::get(call_inception_ty, 
                "pushq $0; ret\n", "imr,~{dirflag},~{fpsr},~{flags}",true);
        CallInst* void_14 = CallInst::Create(ptr_15, inception, "", block);
        void_14->setCallingConv(CallingConv::C);
        void_14->setTailCall(false);
    } else {
        InlineAsm* ptr_15 = InlineAsm::get(call_inception_ty, 
                "pushl $0; ret\n", "i,~{dirflag},~{fpsr},~{flags}",true);
        CallInst* void_14 = CallInst::Create(ptr_15, inception, "", block);
        void_14->setCallingConv(CallingConv::C);
        void_14->setTailCall(false);
    }

    new UnreachableInst(M->getContext(), block);

    return F;

}

void linuxAddCallValue(Module *M) {
    std::vector<Type*>FuncCallValueTy_args;
    unsigned int regWidth = getPointerSize(M);

    Type *intType = IntegerType::get(M->getContext(), regWidth);

    FuncCallValueTy_args.push_back(getVoidPtrType(M->getContext()));
    FuncCallValueTy_args.push_back(intType);

    FunctionType* FuncCallValueTy = FunctionType::get(
            /*Result=*/Type::getVoidTy(M->getContext()),
            /*Params=*/FuncCallValueTy_args,
            /*isVarArg=*/false);

    // if do_call_value has not already been added to this module,
    // then create it
    Function* func_do_call_value = M->getFunction("do_call_value");
    if (!func_do_call_value) {
        func_do_call_value = Function::Create(
                /*Type=*/FuncCallValueTy,
                /*Linkage=*/GlobalValue::ExternalLinkage,
                /*Name=*/"do_call_value", M); 
        func_do_call_value->setCallingConv(CallingConv::C);
        func_do_call_value->addFnAttr(Attribute::AlwaysInline);
    }

} 
