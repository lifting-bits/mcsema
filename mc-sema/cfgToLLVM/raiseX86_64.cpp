
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
        if(fwd_it != fwd_end) {
            int   k = x86_64::getRegisterOffset(RDI);
            Value *rdiFieldGEPV[] = {
                CONST_V<64>(driverBB, 0),
                CONST_V<32>(driverBB, k)
            };

            // make driver take this from register
            fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 1, B));

            Value *rdiP = GetElementPtrInst::CreateInBounds(aCtx, rdiFieldGEPV, "", driverBB);
            Argument  *curArg = &(*fwd_it);
            aliasMCSemaScope(new StoreInst(curArg, rdiP, driverBB));
        }

        // set rsi to arg[1]
        ++fwd_it;
        if(fwd_it != fwd_end) {
            int   k = x86_64::getRegisterOffset(RSI);
            Value *rsiFieldGEPV[] = {
                CONST_V<64>(driverBB, 0),
                CONST_V<32>(driverBB, k)
            };

            // make driver take this from register
            fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 2, B));

            Value *rsiP = GetElementPtrInst::CreateInBounds(aCtx, rsiFieldGEPV, "", driverBB);
            Argument  *curArg = &(*fwd_it);
            aliasMCSemaScope(new StoreInst(curArg, rsiP, driverBB));
        }

        // set rdx to arg[2]
        ++fwd_it;
        if(fwd_it != fwd_end) {
            int   k = x86_64::getRegisterOffset(RDX);
            Value *rdxFieldGEPV[] = {
                CONST_V<64>(driverBB, 0),
                CONST_V<32>(driverBB, k)
            };

            fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 3, B));

            Value *rdxP = GetElementPtrInst::CreateInBounds(aCtx, rdxFieldGEPV, "", driverBB);

            Argument  *curArg = &(*fwd_it);
            aliasMCSemaScope(new StoreInst(curArg, rdxP, driverBB));
        }

        //set rcx to arg[3]
        ++fwd_it;
        if(fwd_it != fwd_end) {
            int   k = x86_64::getRegisterOffset(RCX);
            Value *rcxFieldGEPV[] = {
                CONST_V<64>(driverBB, 0),
                CONST_V<32>(driverBB, k)
            };

            fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 4, B));
            Value *rcxP = GetElementPtrInst::CreateInBounds(aCtx, rcxFieldGEPV, "", driverBB);
            Argument  *curArg = &(*fwd_it);
            aliasMCSemaScope(new StoreInst(curArg, rcxP, driverBB));
        }

        //set r8 to arg[4]
        ++fwd_it;
        if(fwd_it != fwd_end) {
            int   k = x86_64::getRegisterOffset(R8);
            Value *r8FieldGEPV[] = {
                CONST_V<64>(driverBB, 0),
                CONST_V<32>(driverBB, k)
            };

            fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 5, B));

            Value *r8P = GetElementPtrInst::CreateInBounds(aCtx, r8FieldGEPV, "", driverBB);
            Argument  *curArg = &(*fwd_it);
            new StoreInst(curArg, r8P, driverBB);
        }

        //set r9 to arg[5]
        ++fwd_it;
        if(fwd_it != fwd_end) {
            int   k = x86_64::getRegisterOffset(R9);
            Value *r9FieldGEPV[] = {
                CONST_V<64>(driverBB, 0),
                CONST_V<32>(driverBB, k)
            };

            fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 6, B));

            Value *r9P = GetElementPtrInst::CreateInBounds(aCtx, r9FieldGEPV, "", driverBB);
            Argument  *curArg = &(*fwd_it);
            aliasMCSemaScope(new StoreInst(curArg, r9P, driverBB));
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

    F->dump();
    CallInst* ci = CallInst::Create(F, subArg, "", driverBB);
    ci->dump();
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


