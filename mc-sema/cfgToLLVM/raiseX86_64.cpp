
#include "toLLVM.h"
#include "raiseX86.h"
#include "X86.h"
#include "x86Instrs.h"
#include "x86Helpers.h"
#include "ArchOps.h"
#include "RegisterUsage.h"

#include <llvm/Object/COFF.h>
#include <llvm/IR/Constants.h>
#include <llvm/ADT/StringSwitch.h>
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/LinkAllPasses.h"


#include "llvm/IR/Type.h"
#include "Externals.h"
#include "../common/to_string.h"
#include "../common/Defaults.h"

#include <vector>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/MDBuilder.h>
#include "ArchOps.h"

using namespace llvm;
using namespace std;
namespace x86_64 {
bool addEntryPointDriverRaw(Module *M, string name, VA entry) {
    string  s("sub_"+to_string<VA>(entry, hex));
    Function  *F = M->getFunction(s);

    if( F != NULL ) {
        vector<Type *>  args;
        vector<Value*>  subArg;
        args.push_back(g_PRegStruct);
        Type  *returnTy = Type::getVoidTy(M->getContext());
        FunctionType *FT = FunctionType::get(returnTy, args, false);

        // check if driver name already exists.. maybe its the name of an
        // extcall and we will have a serious conflict?

        Function *driverF = M->getFunction(name);
        if(driverF == NULL) {
            // function does not exist. this is good.
            // insert the function prototype
            driverF = (Function *) M->getOrInsertFunction(name, FT);
        } else {
            throw TErr(__LINE__, __FILE__, "Cannot insert driver. Function "+name+" already exists.");
        }


        if( driverF == NULL ) {
          throw TErr(__LINE__, __FILE__, "Could not get or insert function "+name);
        }

        //insert the function logical body
        //insert a primary BB
        BasicBlock  *driverBB = BasicBlock::Create( driverF->getContext(),
                "driverBlockRaw",
                driverF);

        Function::ArgumentListType::iterator  it =
            driverF->getArgumentList().begin();
        Function::ArgumentListType::iterator  end =
            driverF->getArgumentList().end();

        while(it != end) {
            Argument  *curArg = it;
            subArg.push_back(curArg);
            it++;
        }

        CallInst* ci = CallInst::Create(F, subArg, "", driverBB);
        archSetCallingConv(M, ci);
        ReturnInst::Create(driverF->getContext(), driverBB);
        return true;
    }

    return false;
}

bool addEntryPointDriver(Module *M,
        string name,
        VA entry,
        int np,
        bool ret,
        raw_ostream &report,
        ExternalCodeRef::CallingConvention cconv,
        string funcSign)
{
  //convert the VA into a string name of a function, try and look it up
  string  s("sub_"+to_string<VA>(entry, hex));
  Function  *F = M->getFunction(s);
  Type *int64ty = Type::getInt64Ty(M->getContext());
  Type *int64PtrTy = PointerType::get(int64ty, 0);
  Type *doublety = Type::getDoubleTy(M->getContext());
  Type *doublePtrTy = PointerType::get(doublety, 0);

  if( F != NULL ) {
    //build function prototype from name and numParms
    vector<Type *>  args;

    for(int i = 0; i < np; i++) {
      if(funcSign.c_str()[i] == 'F'){
        args.push_back(Type::getDoubleTy(M->getContext()));
      }
      else{
        args.push_back(Type::getInt64Ty(M->getContext()));
      }
    }

    Type  *returnTy = NULL;
    if(ret) {
      returnTy = Type::getInt64Ty(M->getContext());
    } else{
      returnTy = Type::getVoidTy(M->getContext());
    }

    FunctionType *FT = FunctionType::get(returnTy, args, false);
    std::cout << __FUNCTION__ << "\n";
    //insert the function prototype
    Function  *driverF = (Function *) M->getOrInsertFunction(name, FT);
    // set drivers calling convention to match user specification
    archSetCallingConv(M, driverF);

    TASSERT(driverF != NULL, "");

    //insert the function logical body
    //insert a primary BB
    BasicBlock  *driverBB = BasicBlock::Create( driverF->getContext(),
                                                "driverBlock",
                                                driverF);

    //insert an alloca for the register context structure
    Instruction *aCtx = new AllocaInst(g_RegStruct, "", driverBB);
    TASSERT(aCtx != NULL, "Could not allocate register context!");

    //write the parameters into the stack
    Function::ArgumentListType::iterator  fwd_it =
      driverF->getArgumentList().begin();
    Function::ArgumentListType::iterator  fwd_end =
      driverF->getArgumentList().end();

    AttrBuilder B;
    B.addAttribute(Attribute::InReg);

    unsigned fp_stack_num = 0;
    unsigned notfp_stack_num = 0;

    if(getSystemOS(M) == llvm::Triple::Win32) {
        if(fwd_it != fwd_end) {
            Type *T = fwd_it->getType();
            Value *arg1;
            if(T->isDoubleTy()){
                int   k = x86_64::getRegisterOffset(XMM0);
                Value *argFieldGEPV[] = {
                    CONST_V<64>(driverBB, 0),
                    CONST_V<32>(driverBB, k)
                };
                // make driver take this from register
                fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 1, B));

                Instruction *ptr128 = GetElementPtrInst::CreateInBounds(aCtx, argFieldGEPV, "", driverBB);

                arg1 = CastInst::CreatePointerCast(ptr128, PointerType::get(Type::getDoubleTy(M->getContext()), 0), "arg0", driverBB);
            } else {
                int   k = x86_64::getRegisterOffset(RCX);
                Value *argFieldGEPV[] = {
                    CONST_V<64>(driverBB, 0),
                    CONST_V<32>(driverBB, k)
                };
                // make driver take this from register
                fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 1, B));

                arg1 = GetElementPtrInst::CreateInBounds(aCtx, argFieldGEPV, "", driverBB);
            }

            Argument  *curArg = &(*fwd_it);
            aliasMCSemaScope(new StoreInst(curArg, arg1, driverBB));
        }

        ++fwd_it;
        if(fwd_it != fwd_end) {
            Type *T = fwd_it->getType();
            Value *arg2;
            if(T->isDoubleTy()){
                int   k = x86_64::getRegisterOffset(XMM1);
                Value *argFieldGEPV[] = {
                    CONST_V<64>(driverBB, 0),
                    CONST_V<32>(driverBB, k)
                };
                // make driver take this from register
                fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 1, B));

                Instruction *ptr128 = GetElementPtrInst::CreateInBounds(aCtx, argFieldGEPV, "", driverBB);

                arg2 = CastInst::CreatePointerCast(ptr128, PointerType::get(Type::getDoubleTy(M->getContext()), 0), "arg1", driverBB);
            } else {
                int   k = x86_64::getRegisterOffset(RDX);
                Value *argFieldGEPV[] = {
                    CONST_V<64>(driverBB, 0),
                    CONST_V<32>(driverBB, k)
                };
                // make driver take this from register
                fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 2, B));

                arg2 = GetElementPtrInst::CreateInBounds(aCtx, argFieldGEPV, "", driverBB);
            }
            Argument  *curArg = &(*fwd_it);
            aliasMCSemaScope(new StoreInst(curArg, arg2, driverBB));
        }

        ++fwd_it;
        if(fwd_it != fwd_end) {
            Type *T = fwd_it->getType();
            Value *arg3;
            if(T->isDoubleTy()){
                int   k = x86_64::getRegisterOffset(XMM2);
                Value *argFieldGEPV[] = {
                    CONST_V<64>(driverBB, 0),
                    CONST_V<32>(driverBB, k)
                };
                // make driver take this from register
                fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 3, B));

                Instruction *ptr128 = GetElementPtrInst::CreateInBounds(aCtx, argFieldGEPV, "", driverBB);

                arg3 = CastInst::CreatePointerCast(ptr128, PointerType::get(Type::getDoubleTy(M->getContext()), 0), "arg3", driverBB);
            } else {
                int   k = x86_64::getRegisterOffset(R8);
                Value *r8FieldGEPV[] = {
                    CONST_V<64>(driverBB, 0),
                    CONST_V<32>(driverBB, k)
                };

                fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 3, B));

                arg3 = GetElementPtrInst::CreateInBounds(aCtx, r8FieldGEPV, "", driverBB);
            }
            Argument  *curArg = &(*fwd_it);
            new StoreInst(curArg, arg3, driverBB);
        }

        ++fwd_it;
        if(fwd_it != fwd_end) {
            Type *T = fwd_it->getType();
            Value *arg4;
            if(T->isDoubleTy()){
                int   k = x86_64::getRegisterOffset(XMM3);
                Value *argFieldGEPV[] = {
                    CONST_V<64>(driverBB, 0),
                    CONST_V<32>(driverBB, k)
                };
                // make driver take this from register
                fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 1, B));

                Instruction *ptr128 = GetElementPtrInst::CreateInBounds(aCtx, argFieldGEPV, "", driverBB);
                arg4 = CastInst::CreatePointerCast(ptr128, PointerType::get(Type::getDoubleTy(M->getContext()), 0), "arg3", driverBB);
            } else {
                int   k = x86_64::getRegisterOffset(R9);
                Value *r9FieldGEPV[] = {
                    CONST_V<64>(driverBB, 0),
                    CONST_V<32>(driverBB, k)
                };

                fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 4, B));

                arg4 = GetElementPtrInst::CreateInBounds(aCtx, r9FieldGEPV, "", driverBB);
            }
            Argument  *curArg = &(*fwd_it);
            aliasMCSemaScope(new StoreInst(curArg, arg4, driverBB));
        }
    } else if (getSystemOS(M) == llvm::Triple::Linux) {
      //#else
      unsigned fp_reg_num = 0;
      unsigned notfp_reg_num = 0;
      Value *args_fp[8];
      Value *args_notfp[6];
      int reg_offset_fp[8] = {x86_64::getRegisterOffset(XMM0), x86_64::getRegisterOffset(XMM1), x86_64::getRegisterOffset(XMM2), x86_64::getRegisterOffset(XMM3), x86_64::getRegisterOffset(XMM4), x86_64::getRegisterOffset(XMM5), x86_64::getRegisterOffset(XMM6), x86_64::getRegisterOffset(XMM7)};
      int reg_offset_notfp[6] = {x86_64::getRegisterOffset(RDI), x86_64::getRegisterOffset(RSI), x86_64::getRegisterOffset(RDX), x86_64::getRegisterOffset(RCX), x86_64::getRegisterOffset(R8), x86_64::getRegisterOffset(R9)};

      while(fwd_it != fwd_end) {
        Type *T = fwd_it->getType();
        if(T->isDoubleTy()){
          if(fp_reg_num < 8){
            //xmm0-7
            Value *argFieldGEPV[] = {
              CONST_V<64>(driverBB, 0),
              CONST_V<32>(driverBB, reg_offset_fp[fp_reg_num])
            };

            // make driver take this from register
            fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), fp_reg_num, B));
            Instruction *ptr128 = GetElementPtrInst::CreateInBounds(aCtx, argFieldGEPV, "", driverBB);
            args_fp[fp_reg_num] = CastInst::CreatePointerCast(ptr128, PointerType::get(Type::getDoubleTy(M->getContext()), 0), "", driverBB);

            Argument  *curArg = &(*fwd_it);
            new StoreInst(curArg, args_fp[fp_reg_num], driverBB);

            ++fp_reg_num;
          } else {
            ++fp_stack_num;
          }
        } else {
          if(notfp_reg_num < 6){
            //rdi,rsi,rdx,rcx,r8,r9
            Value *argFieldGEPV[] = {
              CONST_V<64>(driverBB, 0),
              CONST_V<32>(driverBB, reg_offset_notfp[notfp_reg_num])
            };

            fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), notfp_reg_num, B));
            args_notfp[notfp_reg_num] = GetElementPtrInst::CreateInBounds(aCtx, argFieldGEPV, "", driverBB);

            Argument  *curArg = &(*fwd_it);
            new StoreInst(curArg, args_notfp[notfp_reg_num], driverBB);

            ++notfp_reg_num;
          } else {
            ++notfp_stack_num;
          }
        }

        ++fwd_it;
      }
    } else { 
        TASSERT(false, "Unsupported OS!");
    }
//#endif
    // rest of the arguments are passed on stack
    Function::ArgumentListType::reverse_iterator it = driverF->getArgumentList().rbegin();
    Function::ArgumentListType::reverse_iterator end = driverF->getArgumentList().rend();

    Value *stackSize = archGetStackSize(M, driverBB);
    Value *aStack = archAllocateStack(M, stackSize, driverBB);

    // position pointer to end of stack
    Value *stackBaseInt = BinaryOperator::Create(BinaryOperator::Add,
            aStack, stackSize, "", driverBB);
    Value *stackPosInt = stackBaseInt;

    // decrement stackPtr to leave some slack space on the stack.
    // our current implementation of varargs functions just passes
    // a big number of arguments to the destination function.
    // This works because they are declared cdecl and the caller cleans up
    // ... BUT
    // if there is not enough stack for all these args, we may dereference
    // unallocated memory. Leave some slack so this doesn't happen.
    stackPosInt = BinaryOperator::Create(BinaryOperator::Sub,
                    stackPosInt, CONST_V<64>(driverBB, 8*12), "", driverBB);

    // decrement stackPtr once to have a slot for
    // "return address", even if there are no arguments
    stackPosInt = BinaryOperator::Create(BinaryOperator::Sub,
                    stackPosInt, CONST_V<64>(driverBB, 8), "", driverBB);

    // number of arguments to be pushed on stack
    int args_to_push = driverF->getArgumentList().size() - 6;

    // save arguments on the stack
    if(getSystemOS(M) == llvm::Triple::Win32) {
       while(args_to_push > 0)
      {
        Argument  *curArg = &(*it);
        // convert to int64 ptr
        Value *stackPosPtr = noAliasMCSemaScope(new IntToPtrInst(stackPosInt, int64PtrTy, "", driverBB ));
        // write argument
        Instruction *k = noAliasMCSemaScope(new StoreInst(curArg, stackPosPtr, driverBB));
        // decrement stack
        stackPosInt = BinaryOperator::Create(BinaryOperator::Sub,
                  stackPosInt, CONST_V<64>(driverBB, 8), "", driverBB);
        ++it;
        --args_to_push;
      }
    } else if (getSystemOS(M) == llvm::Triple::Linux) {
      unsigned param_num = driverF->getFunctionType()->getNumParams() -1;
      Argument *curArg;
      Value *stackPosPtr;
      Instruction *k;

      while(fp_stack_num + notfp_stack_num > 0){
        Type *param_type = driverF->getFunctionType()->getParamType(param_num);
        if(param_type->isDoubleTy()){
          //floating point num
          if(fp_stack_num > 0){
            curArg = &(*it);
            // convert to int64 ptr
            stackPosPtr = noAliasMCSemaScope(new IntToPtrInst(stackPosInt, doublePtrTy, "", driverBB ));
            // write argument
            k = noAliasMCSemaScope(new StoreInst(curArg, stackPosPtr, driverBB));
            // decrement stack
            stackPosInt = BinaryOperator::Create(BinaryOperator::Sub,
                stackPosInt, CONST_V<64>(driverBB, 8), "", driverBB);

            --fp_stack_num;
          }
        } else {
          //not floating point num
          if(notfp_stack_num > 0){
            curArg = &(*it);
            // convert to int64 ptr
            stackPosPtr = noAliasMCSemaScope(new IntToPtrInst(stackPosInt, int64PtrTy, "", driverBB ));
            // write argument
            k = noAliasMCSemaScope(new StoreInst(curArg, stackPosPtr, driverBB));
            // decrement stack
            stackPosInt = BinaryOperator::Create(BinaryOperator::Sub,
                stackPosInt, CONST_V<64>(driverBB, 8), "", driverBB);

            --notfp_stack_num;
          }
        }

        ++it;
        --param_num;
      }
    } else { 
        TASSERT(false, "Unsupported OS!");
    }

    int   k = x86_64::getRegisterOffset(RSP);
    Value *spFieldGEPV[] = {
      CONST_V<64>(driverBB, 0),
      CONST_V<32>(driverBB, k)
    };
    k = x86_64::getRegisterOffset(STACK_BASE);
    Value *stackBaseGEPV[] = {
      CONST_V<64>(driverBB, 0),
      CONST_V<32>(driverBB, k)
    };
    k = x86_64::getRegisterOffset(STACK_LIMIT);
    Value *stackLimitGEPV[] = {
      CONST_V<64>(driverBB, 0),
      CONST_V<32>(driverBB, k)
    };

    Value *spValP =
      GetElementPtrInst::CreateInBounds(aCtx, spFieldGEPV, "", driverBB);

    Value *sBaseValP =
      GetElementPtrInst::CreateInBounds(aCtx, stackBaseGEPV, "", driverBB);

    Value *sLimitValP =
      GetElementPtrInst::CreateInBounds(aCtx, stackLimitGEPV, "", driverBB);

    // stack limit = start of allocation (stack grows down);
    Instruction *tmp1 = aliasMCSemaScope(new StoreInst(aStack, sLimitValP, driverBB));
    // stack base = stack alloc start + stack size
    Instruction *tmp2 = aliasMCSemaScope(new StoreInst(stackBaseInt, sBaseValP, driverBB));

    // all functions assume DF is clear on entry
    k = x86_64::getRegisterOffset(DF);
    Value *dflagGEPV[] = {
      CONST_V<64>(driverBB, 0),
      CONST_V<32>(driverBB, k)
    };

    Value *dflagP =
      GetElementPtrInst::CreateInBounds(aCtx, dflagGEPV, "", driverBB);

    Instruction *tmp3 = aliasMCSemaScope(new StoreInst(CONST_V<1>(driverBB, 0), dflagP, driverBB));

    Instruction *j = aliasMCSemaScope(new StoreInst(stackPosInt, spValP, driverBB));
    TASSERT(j != NULL, "Could not write stack value to RSP");

    //call the sub function with register struct as argument
    vector<Value*>  subArg;
    subArg.push_back(aCtx);

    CallInst* ci = CallInst::Create(F, subArg, "", driverBB);
    archSetCallingConv(M, ci);
    archFreeStack(M, aStack, driverBB);

    //if we are requested, return the EAX value, else return void
    if(ret) {
      //do a GEP and load for the EAX register in the reg structure
      int j = x86_64::getRegisterOffset(RAX);
      Value *raxGEPV[] = {
        CONST_V<64>(driverBB, 0),
        CONST_V<32>(driverBB, j)
      };

      Value *raxVP =
        GetElementPtrInst::CreateInBounds(aCtx, raxGEPV, "", driverBB);
      Instruction *raxV = aliasMCSemaScope(new LoadInst(raxVP, "", driverBB));

      //return that value
      ReturnInst::Create(driverF->getContext(), raxV, driverBB);
    } else {
      ReturnInst::Create(driverF->getContext(), driverBB);
    }

  } else {
      report << "Could not find entry point function\n";
    return false;
  }

  return true;
}

}


