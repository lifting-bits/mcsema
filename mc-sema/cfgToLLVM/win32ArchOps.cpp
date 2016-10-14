#if 0
#include <string>
#include <iostream>
#include <vector>

#include "win32cb.h"
#include "win32ArchOps.h"

#include "llvm/IR/Module.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InlineAsm.h"

#include "TransExcn.h"
#include "raiseX86.h"
#include "RegisterUsage.h"
#include "ArchOps.h"

#include "../common/to_string.h"

using namespace llvm;
using namespace std;

extern llvm::GlobalVariable* g_StateBackup;
extern llvm::PointerType *g_PRegStruct;

static bool added_callbacks = false;

static CallingConv::ID getCallingConv(Module *M){
	if(getSystemArch(M) == _X86_){
		return CallingConv::C;
	} else {
		return CallingConv::X86_64_Win64;
	}
}

// GEP to get a reg from pro_int_call return
#define READ_REG_OPAQUE64(varname, reg, opaque) do {  \
        int   reg_off = x86_64::getRegisterOffset(reg);        \
        Value *reg_GEPV[] = {                       \
          CONST_V<64>(driver_block, 0),             \
          CONST_V<32>(driver_block, reg_off)        \
        };                                          \
        varname = GetElementPtrInst::Create(        \
                 opaque,                            \
                 reg_GEPV,                          \
                 "",                                \
                 driver_block);                     \
    } while(0);

// GEP to get a reg from pro_int_call return
#define READ_REG_OPAQUE(varname, reg, opaque) do {  \
        int   reg_off = x86::getRegisterOffset(reg);        \
        Value *reg_GEPV[] = {                       \
          CONST_V<32>(driver_block, 0),             \
          CONST_V<32>(driver_block, reg_off)        \
        };                                          \
        varname = GetElementPtrInst::Create(        \
                 opaque,                            \
                 reg_GEPV,                          \
                 "",                                \
                 driver_block);                     \
    } while(0);                                     

static Function *getCallbackPrologueInternal(Module *M) {

    // should be created by archAddCallbacksToModule()
    Function *F = M->getFunction("callback_adapter_prologue_internal");
    TASSERT(F != NULL, "Want to use callback_adapter_prologue_internal, but its not defined");

    return F;
}

static Function *getCallbackEpilogue(Module *M) {
    
    Function *F = M->getFunction("callback_adapter_epilogue");
    TASSERT(F != NULL, "Want to use callback_adapter_epilogue but its not defined");    
    return F;
}

// type of internal callback handler
static FunctionType    *GetCBInternalFnTy(Module *M) {

	unsigned regWidth = getPointerSize(M);
    Type *intTy = Type::getIntNTy(M->getContext(), regWidth);
    Type *intPtrTy = PointerType::get(IntegerType::get(M->getContext(), regWidth), 0);
    Type *voidstar = PointerType::get(
            Type::getInt8Ty(M->getContext()), 
            0);

    std::vector<Type*>	cb_internal_args;
    cb_internal_args.push_back(intPtrTy);     // int *retv
    cb_internal_args.push_back(voidstar);       // void* esp
    cb_internal_args.push_back(intTy);        // int ebp
    FunctionType    *FuncTy_CBInternal = 
        FunctionType::get(intTy,
                cb_internal_args,
                false);

    return FuncTy_CBInternal;
}

static Function *win32MakeCallbackInternal(Module *M, VA local_target) {
    // no driver, make one
    std::string			fname = "callback_sub_"+
        to_string<VA>(local_target, std::hex)+
        "_internal";
    FunctionType    *callbackTy = GetCBInternalFnTy(M);
    Type *voidstar = PointerType::get(
            Type::getInt8Ty(M->getContext()), 
            0);
    Function *Fpro_internal = getCallbackPrologueInternal(M);
    Function *Fepi = getCallbackEpilogue(M);
    //Type *int32ty = Type::getInt32Ty(M->getContext());


    Function *F = dynamic_cast<Function*>(M->getOrInsertFunction(fname, callbackTy));
    TASSERT( F != NULL, "" );
    F->setLinkage(GlobalValue::InternalLinkage);
    F->setCallingConv(CallingConv::C);

    // get reference to function arguments
    Function::arg_iterator args = F->arg_begin();
    Value* arg_ESPDIFF = args++;
    arg_ESPDIFF->setName("arg_ESPDIFF");
    Value* arg_ESP = args++;
    arg_ESP->setName("arg_ESP");
    Value* arg_EBP = args++;
    arg_EBP->setName("arg_EBP");

    // add code to driver
    BasicBlock *driver_block = BasicBlock::Create(
        F->getContext(), "", F);

    // allocate pointer to hold new stack
    Instruction *new_stack = new AllocaInst(voidstar, "", driver_block);

    // get ready to call callback_adapter_internal
    std::vector<Value*>	pro_args;
    pro_args.push_back(arg_EBP);    // int32
    pro_args.push_back(arg_ESP);    // void*
    pro_args.push_back(new_stack);  // void**

    // call callback_adapter_internal
    CallInst *pro_int_call = CallInst::Create(Fpro_internal, pro_args, "", driver_block);
    pro_int_call->setCallingConv(CallingConv::X86_StdCall);


    // cast to g_pRegState?


    // old_esp = rs->ESP
    // GEP to get ESP from pro_int_call return
    Value *rs_esp;

    if(getSystemArch(M) == _X86_64_) {
        READ_REG_OPAQUE64(rs_esp, RSP, pro_int_call);
    } else {
        READ_REG_OPAQUE(rs_esp, ESP, pro_int_call);
    }

    LoadInst* orig_ESP = new LoadInst(rs_esp, "", false, driver_block);
    

    // call original functions
    std::string			realfn = "sub_"+to_string<VA>(local_target, std::hex);
    Function        *Freal = M->getFunction(realfn);
    TASSERT(Freal != NULL, "Cannot find original function: "+realfn);

    Value *gpreg_struct = CastInst::CreatePointerCast(pro_int_call, 
            g_PRegStruct, 
            "", 
            driver_block);
#if 0
    std::vector<Value*>	realArgs;
    realArgs.push_back(gpreg_struct);

	CallInst *real_call = CallInst::Create(Freal, realArgs, "", driver_block);
    real_call->setCallingConv(CallingConv::X86_StdCall);
    real_call->setIsNoInline();
#endif
    // retv = rs->EAX;
    Value *rs_eax;
    if(getSystemArch(M) == _X86_64_) {
        READ_REG_OPAQUE64(rs_eax, RAX, gpreg_struct);
    } else {
        READ_REG_OPAQUE(rs_eax, EAX, gpreg_struct);
    }
    LoadInst *eax_val = new LoadInst(rs_eax, "", false, driver_block);


    // *esp_diff = orig_esp - rs->ESP;
    Value *rs_esp_new;
    if(getSystemArch(M) == _X86_64_) {
        READ_REG_OPAQUE64(rs_esp_new, RSP, gpreg_struct);
    } else {
        READ_REG_OPAQUE(rs_esp_new, ESP, gpreg_struct);
    }

    LoadInst* new_esp_val = new LoadInst(rs_esp_new, "", false, driver_block);
    Value *esp_diff = BinaryOperator::Create(
            Instruction::Sub, 
            orig_ESP, 
            new_esp_val, 
            "", 
            driver_block);

    StoreInst *save_retv = new StoreInst(esp_diff, arg_ESPDIFF, false, driver_block);
    // call epilogue
    Value *ns_deref = new LoadInst(new_stack, "", driver_block);
    std::vector<Value*>	epi_args;
    epi_args.push_back(gpreg_struct);
    epi_args.push_back(ns_deref);
    
	CallInst *epi_call = CallInst::Create(Fepi, epi_args, "", driver_block);
	epi_call->setCallingConv(CallingConv::X86_StdCall);

    // return value = eax
    llvm::ReturnInst::Create(F->getContext(), eax_val, driver_block);

    return F;

}

static Function *win32MakeCallbackStub(Module *M, VA local_target) {

    //lookup local function in the module
	unsigned regWidth = getPointerSize(M);

    std::string			fname = "callback_sub_"+to_string<VA>(local_target, std::hex);

    std::string			call_tgt_name = "callback_sub_"+
        to_string<VA>(local_target, std::hex)+
        "_internal";

    Function        *call_tgt = M->getFunction(call_tgt_name);
    TASSERT(call_tgt != NULL, "Cannot find call target function in callback stub");

    // no driver, make one
    FunctionType    *callbackTy = 
        FunctionType::get( Type::getIntNTy(M->getContext(), regWidth), false );

    Function *F = dynamic_cast<Function*>(M->getOrInsertFunction(fname, callbackTy));
    TASSERT( F != NULL, "Cannot create callback stub" );
    F->setLinkage(GlobalValue::InternalLinkage);
    F->addFnAttr(Attribute::Naked);

    // add code to driver
    BasicBlock *driver_block = BasicBlock::Create(
            F->getContext(), "", F);
    
    std::vector<Type*>	cb_args;
    cb_args.push_back(PointerType::get(GetCBInternalFnTy(M), 0));
    FunctionType    *FuncTy_CBStub = FunctionType::get(
                // int32 return since the function needs this prototype
                Type::getIntNTy(M->getContext(), regWidth),
                cb_args,
                false);
    InlineAsm* func_body = nullptr;
    if(getSystemArch(M) == _X86_64_) {
        func_body = InlineAsm::get(FuncTy_CBStub,
                "movq	%rsp, %rdx\n"
                "subq	$$8, %rsp\n"
                "movq   %rbp, %r9\n"
                "movq	%rsp, %rax\n"
                "subq	$$8, %rax\n"
                "movq   %rax, %rcx\n"
                "call	${1:P}\n"
                "movq	(%rsp), %rcx\n"
                "subq	%rcx, %rsp\n"
                "jmpq	*(%rsp,%rcx)\n",
                "={rax},*imr,~{rax},~{rcx},~{rdx},~{r9},~{dirflag},~{fpsr},~{flags}",
                true);
    } else {
        func_body = InlineAsm::get(FuncTy_CBStub, 
                "movl	%esp, %eax\n"
                "subl	$$4, %esp\n"
                "pushl	%ebp\n"
                "pushl	%eax\n"
                "subl	$$4, %eax\n"
                "pushl	%eax\n"
                "calll	$1\n"
                "addl   $$12, %esp\n"
                "movl	(%esp), %ecx\n"
                "addl	$$4, %esp\n"
                "subl	%ecx, %esp\n"
                "jmpl	*(%esp,%ecx)\n",
                "={eax},*imr,~{eax},~{ecx},~{dirflag},~{fpsr},~{flags}",
                true);
    }
    std::vector<Value*> asm_args;
    asm_args.push_back(call_tgt);

    CallInst* do_asm = CallInst::Create(func_body, asm_args, "", driver_block);
    do_asm->setTailCall(true);

    // will never get here
    llvm::ReturnInst::Create(F->getContext(), do_asm, driver_block);

    return F;
}

llvm::Function *win32MakeCallbackForLocalFunction(Module *M, VA local_target) {
    if(!added_callbacks) {
        std::cout << __FUNCTION__ << ": Adding Callbacks to Module!" << std::endl;
        addWin32CallbacksToModule(M);
        added_callbacks = true;
    }


    //lookup local function in the module
    std::string			fname = "callback_sub_"+to_string<VA>(local_target, std::hex);
    Function        *F = M->getFunction(fname);

    // we already created a callback for this, re-use it.
    if(F != NULL) {
        return F;
    }

    Function *F_int = win32MakeCallbackInternal(M, local_target);
    Function *F_stub = win32MakeCallbackStub(M, local_target);


    return F_stub;
}

static void call_with_alt_stack(Module* M, 
                                Value *new_esp, 
                                Value *target_fn, 
                                Value *old_esp,
                                Value *retval,
                                Value *new_esp_val,
                                BasicBlock *B) 
{
    std::vector<Type*>SetEspTy_args;
    unsigned regWidth = getPointerSize(M);

    Type *int32ty = IntegerType::getIntNTy(M->getContext(), regWidth);
    PointerType* int32ty_ptr = PointerType::get(int32ty, 0);

    std::vector<Type*>NoArgFuncTy_args;

    PointerType* Int8PtrTy = PointerType::get(IntegerType::get(M->getContext(), 8), 0);

    FunctionType* NoArgFuncTy = FunctionType::get(
    /*Result=*/Int8PtrTy,
    /*Params=*/NoArgFuncTy_args,
    /*isVarArg=*/false);
    PointerType* NoArgFuncPtrTy = PointerType::get(NoArgFuncTy, 0);

    SetEspTy_args.push_back(int32ty);
    SetEspTy_args.push_back(NoArgFuncPtrTy);
    SetEspTy_args.push_back(int32ty);
    SetEspTy_args.push_back(int32ty_ptr);
    SetEspTy_args.push_back(int32ty_ptr);


    if(new_esp->getType() != int32ty) {
      new_esp = llvm::CastInst::CreatePointerCast(new_esp, int32ty, "", B);
    }

    if(old_esp->getType() != int32ty) {
      old_esp = llvm::CastInst::CreatePointerCast(old_esp, int32ty, "", B);
    }

    FunctionType* SetEspTy = FunctionType::get(
            /*Result=*/Type::getVoidTy(M->getContext()),
            /*Params=*/SetEspTy_args,
            /*isVarArg=*/false);
    InlineAsm* ptr_26 = nullptr;
    if(getSystemArch(M) == _X86_64_) {
        ptr_26 = InlineAsm::get(SetEspTy,
                "movq $0, %rsp\n" // real esp = translator esp
                "callq *$1\n"     // call the unkown function
                "pushq %rax\n"    // save return value
                "movq %rsp, %rax\n" // save pointer to return value and the esp val
                "movq $2, %rsp\n" // restore orignal esp
                "movq (%rax), %rcx\n"
                "movq %rcx, $3\n" // get the return value
                "leaq 8(%rax), %rcx\n" // get original esp value (before push eax)
                "movq %rcx, $4\n",
                // eax, ecx, edx, can be clobbered by stdcall and cdecl functions
                "mr,r,r,*mr,*mr,~{rax},~{rcx},~{rdx},~{dirflag},~{fpsr},~{flags}",
                true);
    } else {
        ptr_26 = InlineAsm::get(SetEspTy, 
                "movl $0, %esp\n" // real esp = translator esp
                "calll *$1\n"     // call the unkown function
                "pushl %eax\n"    // save return value
                "movl %esp, %eax\n" // save pointer to return value and the esp val
                "movl $2, %esp\n" // restore orignal esp
                "movl (%eax), %ecx\n"
                "movl %ecx, $3\n" // get the return value
                "leal 4(%eax), %ecx\n" // get original esp value (before push eax)
                "movl %ecx, $4\n",
                // eax, ecx, edx, can be clobbered by stdcall and cdecl functions
                "mr,r,r,*mr,*mr,~{eax},~{ecx},~{edx},~{dirflag},~{fpsr},~{flags}",
                true);
    }
    vector<Value*> set_esp_args;
    set_esp_args.push_back(new_esp);
    set_esp_args.push_back(target_fn);
    set_esp_args.push_back(old_esp);
    set_esp_args.push_back(retval);
    set_esp_args.push_back(new_esp_val);



    Value *tib = win32GetTib(B);
    // Save current stack base
    Value *sbase = win32GetStackBase(tib, B);

    // Save current stack limit
    Value *slimit = win32GetStackLimit(tib, B);

    // save current allocation base
    Value *abase = win32GetAllocationBase(tib, B);


    // real thread base = context thread base
    Value *new_sbase = GENERIC_READREG(B, STACK_BASE);
    win32SetStackBase(tib, B, new_sbase);

    // real thread limit = context thread limit
    // also to avoid complexity, make commit size == reserve size
    // and hence allocation base == stack limit
    Value *new_slimit = GENERIC_READREG(B, STACK_LIMIT);
    win32SetStackLimit(tib, B, new_slimit);
    win32SetAllocationBase(tib, B, new_slimit);

    CallInst* void_25 = CallInst::Create(ptr_26, set_esp_args, "", B);

    // restore original thread's stack information
    win32SetStackBase(tib, B, sbase);
    win32SetStackLimit(tib, B, slimit);
    win32SetAllocationBase(tib, B, abase);

    // assume all calls clear the direction flag
    // which is normal microsoft calling convention assumption
    F_CLEAR(B, DF);
}

// this function is partially adapted from
// CPPBackend output. 
void win32AddCallValue(Module *mod) {

    unsigned regWidth = getPointerSize(mod);


    // Type Definitions
    PointerType* Int8PtrTy = PointerType::get(IntegerType::get(mod->getContext(), 8), 0);

    std::vector<Type*>FuncCallValueTy_args;

    Type *integerTy = IntegerType::getIntNTy(mod->getContext(), regWidth);
    PointerType* integerTy_ptr = PointerType::get(integerTy, 0);

    FuncCallValueTy_args.push_back(g_PRegStruct);
    FuncCallValueTy_args.push_back(integerTy);

    FunctionType* FuncCallValueTy = FunctionType::get(
            /*Result=*/Type::getVoidTy(mod->getContext()),
            /*Params=*/FuncCallValueTy_args,
            /*isVarArg=*/false);

    std::vector<Type*>GetEspTy_args;
    GetEspTy_args.push_back(integerTy_ptr);
    FunctionType* GetEspTy = FunctionType::get(
            /*Result=*/Type::getVoidTy(mod->getContext()),
            /*Params=*/GetEspTy_args,
            /*isVarArg=*/false);


    std::vector<Type*>NoArgFuncTy_args;
    FunctionType* NoArgFuncTy = FunctionType::get(
            /*Result=*/Int8PtrTy,
            /*Params=*/NoArgFuncTy_args,
            /*isVarArg=*/false);

    PointerType* NoArgFuncPtrTy = PointerType::get(NoArgFuncTy, 0);


    // Function Declarations

    Function* func_do_call_value = mod->getFunction("do_call_value");

    // if do_call_value has not already been added to this module,
    // then create it
    if (!func_do_call_value) {
        func_do_call_value = Function::Create(
                /*Type=*/FuncCallValueTy,
                /*Linkage=*/GlobalValue::InternalLinkage,
                /*Name=*/"do_call_value", mod); 
        func_do_call_value->setCallingConv(getCallingConv(mod)/*CallingConv::C*/);
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


        BasicBlock* main_block = BasicBlock::Create(mod->getContext(), "",func_do_call_value,0);

        // spill locals and get all registers from
        // struct.regs
        allocateLocals(func_do_call_value, regWidth);
        writeContextToLocals(main_block, regWidth, ABICallSpill);

        // create a pointer from the register value that would
        // have been passed in here. 
        // We can't call an int32, need to call a function pointer
        Value *target_fn = new llvm::IntToPtrInst(arg1, NoArgFuncPtrTy, "", main_block);

        // temporarily hold the current ESP/RSP value
        AllocaInst* temp_var = new AllocaInst(integerTy, "", main_block);

        // read ESP/RSP value
        InlineAsm* get_esp_asm = nullptr;
        if (getSystemArch(mod) == _X86_64_) {
            get_esp_asm = InlineAsm::get(GetEspTy, "movq %rsp, $0", "=*imr,~{dirflag},~{fpsr},~{flags}",false);
        } else if (getSystemArch(mod) == _X86_) {
            get_esp_asm = InlineAsm::get(GetEspTy, "movl %esp, $0", "=*imr,~{dirflag},~{fpsr},~{flags}",false);
        } else {
            // unsupported arch
            TASSERT(false, "Unsupported architecturen in target triple");
        }

        vector<Value*> get_esp_args;
        get_esp_args.push_back(temp_var);
        CallInst* ignored_value = CallInst::Create(get_esp_asm, get_esp_args, "", main_block);
        ignored_value->setCallingConv(CallingConv::X86_StdCall);


        //////////////////////////////////////////////////////////////////////////////
        Value *tib = win32GetTib(main_block);
        // Save current stack base
        Value *sbase = win32GetStackBase(tib, main_block);

        // Save current stack limit
        Value *slimit = win32GetStackLimit(tib, main_block);

        // save current allocation base
        Value *abase = win32GetAllocationBase(tib, main_block);


        // real thread base = context thread base
        Value *new_sbase = GENERIC_READREG(main_block, STACK_BASE);
        win32SetStackBase(tib, main_block, new_sbase);

        // real thread limit = context thread limit
        // also to avoid complexity, make commit size == reserve size
        // and hence allocation base == stack limit
        Value *new_slimit = GENERIC_READREG(main_block, STACK_LIMIT);
        win32SetStackLimit(tib, main_block, new_slimit);
        win32SetAllocationBase(tib, main_block, new_slimit);
        /////////////////////////////////////////////////////////////////////////////

        // convert ESP to an integer value
        LoadInst *int_esp_val = new LoadInst(temp_var, "", main_block);
        // and save it in a TLS value
        StoreInst* save_esp = new StoreInst(int_esp_val, g_StateBackup, true, main_block);

        // read the esp value in struct.regs
        Value *reg_esp = nullptr;
        if (getSystemArch(mod) == _X86_64_) {
            reg_esp = R_READ<64>(main_block, X86::RSP);
        } else if (getSystemArch(mod) == _X86_) {
            reg_esp = R_READ<32>(main_block, X86::ESP);
        } else {
            // unsupported arch
            TASSERT(false, "Unsupported architecturen in target triple");
        }

        Value *old_esp = new LoadInst(g_StateBackup ,"", main_block);
        //Value *reg_esp = reg_read_custom(arg0, "ESP", main_block);

        // set esp to reg_esp
        // call target_fn
        // restore esp to old_esp
        // save EAX in retv
        Value *retv = new AllocaInst(integerTy, "", main_block);
        Value *new_esp = new AllocaInst(integerTy, "", main_block);


        call_with_alt_stack(mod, reg_esp, target_fn, old_esp, retv, new_esp, main_block);

        // write eax to register context
        LoadInst *retv_val = new LoadInst(retv, "", main_block);
        LoadInst *new_esp_val = new LoadInst(new_esp, "", main_block);
        if (getSystemArch(mod) == _X86_64_) {
            R_WRITE<64>(main_block, X86::RAX, retv_val);
            R_WRITE<64>(main_block, X86::RSP, new_esp_val);
        } else if (getSystemArch(mod) == _X86_) {
            R_WRITE<32>(main_block, X86::EAX, retv_val);
            R_WRITE<32>(main_block, X86::ESP, new_esp_val);
        } else {
            // unsupported arch
            TASSERT(false, "Unsupported architecturen in target triple");
        }
        //////////////////////////////////////////////////////
        // restore original thread's stack information
        win32SetStackBase(tib,main_block, sbase);
        win32SetStackLimit(tib,main_block, slimit);
        win32SetAllocationBase(tib,main_block, abase);
        /////////////////////////////////////////////////////

        writeLocalsToContext(main_block, regWidth, ABIRetStore);

        // return
        ReturnInst::Create(mod->getContext(), main_block);

    }

}

#endif