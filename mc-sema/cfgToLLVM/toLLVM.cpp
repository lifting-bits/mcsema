/*
Copyright (c) 2013, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of the {organization} nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include "toLLVM.h"
#include "raiseX86.h"
#include "X86.h"
#include "win32cb.h"
#include "InstructionDispatch.h"
#include <llvm/InlineAsm.h>
#include <llvm/BasicBlock.h>
#include <llvm/InstrTypes.h>
#include <cstdio>

using namespace llvm;
using namespace std;

StructType  *g_RegStruct;
PointerType *g_PRegStruct;
GlobalVariable* g_StateBackup;


static void call_with_alt_stack(Module* M, 
                                Value *new_esp, 
                                Value *target_fn, 
                                Value *old_esp,
                                Value *retval,
                                Value *new_esp_val,
                                BasicBlock *B) 
{
    std::vector<Type*>SetEspTy_args;
    Type *int32ty = IntegerType::getInt32Ty(M->getContext());
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

    InlineAsm* ptr_26 = InlineAsm::get(SetEspTy, 
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
    Value *new_sbase = GENERIC_READREG(B, "STACK_BASE");
    win32SetStackBase(tib, B, new_sbase);

    // real thread limit = context thread limit
    // also to avoid complexity, make commit size == reserve size
    // and hence allocation base == stack limit
    Value *new_slimit = GENERIC_READREG(B, "STACK_LIMIT");
    win32SetStackLimit(tib, B, new_slimit);
    win32SetAllocationBase(tib, B, new_slimit);

    CallInst* void_25 = CallInst::Create(ptr_26, set_esp_args, "", B);

    // restore original thread's stack information
    win32SetStackBase(tib, B, sbase);
    win32SetStackLimit(tib, B, slimit);
    win32SetAllocationBase(tib, B, abase);

    // assume all calls clear the direction flag
    // which is normal microsoft calling convention assumption
    F_CLEAR(B, "DF");
}

// this function is partially adapted from
// CPPBackend output. 
static void create_call_value(Module *mod) {

 // Type Definitions
 PointerType* Int8PtrTy = PointerType::get(IntegerType::get(mod->getContext(), 8), 0);
 
 std::vector<Type*>FuncCallValueTy_args;
 
 Type *int32ty = IntegerType::getInt32Ty(mod->getContext());
 PointerType* int32ty_ptr = PointerType::get(int32ty, 0);
 
 FuncCallValueTy_args.push_back(g_PRegStruct);
 FuncCallValueTy_args.push_back(int32ty);

 FunctionType* FuncCallValueTy = FunctionType::get(
  /*Result=*/Type::getVoidTy(mod->getContext()),
  /*Params=*/FuncCallValueTy_args,
  /*isVarArg=*/false);

 std::vector<Type*>GetEspTy_args;
 GetEspTy_args.push_back(int32ty_ptr);
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
     func_do_call_value->setCallingConv(CallingConv::C);
     func_do_call_value->addFnAttr(Attributes::AlwaysInline);
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
  allocateLocals(func_do_call_value, 32);
  writeContextToLocals(main_block, 32);

  // create a pointer from the register value that would
  // have been passed in here. 
  // We can't call an int32, need to call a function pointer
  Value *target_fn = new llvm::IntToPtrInst(arg1, NoArgFuncPtrTy, "", main_block);

  // temporarily hold the current ESP value
  AllocaInst* temp_var = new AllocaInst(int32ty, "", main_block);

  // read ESP value
  InlineAsm* get_esp_asm = InlineAsm::get(GetEspTy, "movl %esp, $0", "=*imr,~{dirflag},~{fpsr},~{flags}",false);
  vector<Value*> get_esp_args;
  get_esp_args.push_back(temp_var);
  CallInst* ignored_value = CallInst::Create(get_esp_asm, get_esp_args, "", main_block);


  //////////////////////////////////////////////////////////////////////////////
    Value *tib = win32GetTib(main_block);
    // Save current stack base
    Value *sbase = win32GetStackBase(tib, main_block);

    // Save current stack limit
    Value *slimit = win32GetStackLimit(tib, main_block);

    // save current allocation base
    Value *abase = win32GetAllocationBase(tib, main_block);


    // real thread base = context thread base
    Value *new_sbase = GENERIC_READREG(main_block, "STACK_BASE");
    win32SetStackBase(tib, main_block, new_sbase);

    // real thread limit = context thread limit
    // also to avoid complexity, make commit size == reserve size
    // and hence allocation base == stack limit
    Value *new_slimit = GENERIC_READREG(main_block, "STACK_LIMIT");
    win32SetStackLimit(tib, main_block, new_slimit);
    win32SetAllocationBase(tib, main_block, new_slimit);
  /////////////////////////////////////////////////////////////////////////////

  // convert ESP to an integer value
  LoadInst *int_esp_val = new LoadInst(temp_var, "", main_block);
  // and save it in a TLS value
  StoreInst* save_esp = new StoreInst(int_esp_val, g_StateBackup, true, main_block);

  // read the esp value in struct.regs
  Value *reg_esp = R_READ<32>(main_block, X86::ESP);
  Value *old_esp = new LoadInst(g_StateBackup ,"", main_block);
  //Value *reg_esp = reg_read_custom(arg0, "ESP", main_block);

  // set esp to reg_esp
  // call target_fn
  // restore esp to old_esp
  // save EAX in retv
  Value *retv = new AllocaInst(int32ty, "", main_block);
  Value *new_esp = new AllocaInst(int32ty, "", main_block);


  call_with_alt_stack(mod, reg_esp, target_fn, old_esp, retv, new_esp, main_block);

  // write eax to register context
  LoadInst *retv_val = new LoadInst(retv, "", main_block);
  LoadInst *new_esp_val = new LoadInst(new_esp, "", main_block);
  R_WRITE<32>(main_block, X86::EAX, retv_val);
  R_WRITE<32>(main_block, X86::ESP, new_esp_val);

  //////////////////////////////////////////////////////
    // restore original thread's stack information
    win32SetStackBase(tib,main_block, sbase);
    win32SetStackLimit(tib,main_block, slimit);
    win32SetAllocationBase(tib,main_block, abase);
  /////////////////////////////////////////////////////


  writeLocalsToContext(main_block, 32);
  
  // return
  ReturnInst::Create(mod->getContext(), main_block);
  
 }

}

FunctionType    *getBaseFunctionType(Module *M) {
    vector<Type *>  baseFunctionArgs;
    baseFunctionArgs.push_back(g_PRegStruct);
    FunctionType    *funcTy = FunctionType::get(
                                        Type::getVoidTy(M->getContext()),
                                        baseFunctionArgs,
                                        false);
    TASSERT(funcTy != NULL, "");

    return funcTy;
}

void doGlobalInit(Module *M) {
    //create the "reg" struct type
    StructType  *regs = StructType::create(M->getContext(), "struct.regs");
    vector<Type *>  regFields;

    initInstructionDispatch();

    //UPDATEREGS -- when we add something to 'regs', add it here
    //GPRs 
    regFields.push_back(IntegerType::get(M->getContext(), 32)); // EAX // 0
    regFields.push_back(IntegerType::get(M->getContext(), 32)); // EBX // 1
    regFields.push_back(IntegerType::get(M->getContext(), 32)); // ECX // 2
    regFields.push_back(IntegerType::get(M->getContext(), 32)); // EDX // 3
    regFields.push_back(IntegerType::get(M->getContext(), 32)); // ESI // 4
    regFields.push_back(IntegerType::get(M->getContext(), 32)); // EDI // 5
    regFields.push_back(IntegerType::get(M->getContext(), 32)); // ESP // 6
    regFields.push_back(IntegerType::get(M->getContext(), 32)); // EBP // 7
                                                                // 32 bytes

    //flags
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // CF // 8
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // PF // 9
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // AF // 10
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // ZF // 11
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // SF // 12
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // OF // 13
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // DF // 14
                                                                   // 28 bytes

    // FPU
    ArrayType  *fpu_regs = ArrayType::get(Type::getX86_FP80Ty(M->getContext()), 8);
    regFields.push_back(fpu_regs);                                 // 80 bytes // 15
    
    // FPU Status Word
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // FPU BUSY // 16
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Condition Code C3 // 17
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // TOP OF STACK // 18
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Condition Code C2 // 19
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Condition Code C1 // 20
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Condition Code C0 // 21
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Error Summary Status // 22
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Stack Fault // 23
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Precision Flag // 24 
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Underflow Flag // 25
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Overflow Flag // 26
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // ZeroDivide Flag // 27
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Denormalized Operand Flag // 28
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Invalid Operation Flag // 29
                                                                   // 56 bytes

    // 80 + 56 + 28 + 32 = 196 bytes

    
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // FPU Infinity Flag // 30
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // FPU Rounding Control // 31
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // FPU Precision Control // 32
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // FPU Precision Mask // 33
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // FPU Underflow Mask // 34
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // FPU Overflow Mask // 35
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // FPU Zero Divide Mask // 36
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // FPU Denormal Operand Mask // 37
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // FPU Invalid Operation Mask // 38

    // FPU tag word; 8 element array of 2-bit entries
    ArrayType  *fpu_tag_word = ArrayType::get(Type::getIntNTy(M->getContext(), 8), 8);
    regFields.push_back(fpu_tag_word);                                 // 80 bytes // 39

    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Last Instruction Ptr Segment 40
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Last Instruction Ptr Offset 41
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Last Data Ptr Segment 42
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Last Data Ptr Offset 43
    
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // FPU FOPCODE 44

    // vector registers
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM0 45
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM1 46
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM2 47
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM3 48
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM4 49
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM5 50
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM6 51
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM7 52

    // non-register values in structRegs
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // 53: stack base (biggest value)
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // 54: stack limit (smallest value)
    

    PointerType *ptrToRegs = PointerType::get(regs, 0);
    regs->setBody(regFields, true);

    vector<Type*> callValArgs;
    callValArgs.push_back(Type::getInt32Ty(M->getContext()));
    callValArgs.push_back(ptrToRegs);

    FunctionType  *callVal = FunctionType::get(
                                      Type::getVoidTy(M->getContext()),
                                      callValArgs,
                                      false);

    //GlobalVariable* g_StateBackup = 
    //    new GlobalVariable(*M, regs, false, GlobalValue::ExternalLinkage, 0, "state.backup");
    Type *int32ty = IntegerType::getInt32Ty(M->getContext());
    g_StateBackup = new GlobalVariable(*M, int32ty, 
                false, 
                GlobalValue::PrivateLinkage, 
                0, 
                "state.backup");
    g_StateBackup->setThreadLocalMode(GlobalVariable::GeneralDynamicTLSModel);


    Constant *zero = ConstantInt::get(int32ty, 0, false);
    g_StateBackup->setInitializer(zero);
    


    g_RegStruct = regs;
    g_PRegStruct = ptrToRegs;

    create_call_value(M);

    return;
}
