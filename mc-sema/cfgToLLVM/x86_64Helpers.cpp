
#include "toLLVM.h"
#include "raiseX86.h"
#include "Externals.h"
#include "X86.h"
#include "x86Helpers.h"
#include "../common/to_string.h"
#include "llvm/Support/Debug.h"

using namespace std;
using namespace llvm;

namespace x86_64 {
	
Value *getAddrFromExpr( BasicBlock      *b,
                        NativeModulePtr mod,
                        const MCOperand &Obase,
                        const MCOperand &Oscale,
                        const MCOperand &Oindex,
                        const int64_t Odisp,
                        const MCOperand &Oseg,
                        bool dataOffset) 
{
    TASSERT(Obase.isReg(), "");
    TASSERT(Oscale.isImm(), "");
    TASSERT(Oindex.isReg(), "");
    TASSERT(Oseg.isReg(), "");

    unsigned    baseReg = Obase.getReg();
    int64_t     disp = Odisp;
	
	// specific function for 64 bit
    Value       *d = NULL;
    IntegerType *iTy = IntegerType::getInt64Ty(b->getContext());

    if( dataOffset ||  
        (mod && disp && baseReg != X86::RBP && baseReg!= X86::RSP) ) 
    {
        VA  baseGlobal;
        if( addrIsInData(disp, mod, baseGlobal, dataOffset ? 0 : 0x1000) ) {
            //we should be able to find a reference to this in global data 
            Module  *M = b->getParent()->getParent();
            string  sn = "data_0x" + to_string<VA>(baseGlobal, hex);
            GlobalVariable *gData = M->getNamedGlobal(sn);

            //if we thought it was a global, we should be able to
            //pin it to a global array we made during module setup
            if( gData == NULL) 
              throw TErr(__LINE__, __FILE__, "Global variable not found");

            // since globals are now a structure 
            // we cannot simply slice into them.
            // Need to get ptr and then add integer displacement to ptr
            Value   *globalGEPV[] =  
                {   ConstantInt::get(Type::getInt64Ty(b->getContext()), 0), 
                    ConstantInt::get(Type::getInt32Ty(b->getContext()), 0)};
            Instruction *globalGEP = 
                GetElementPtrInst::Create(gData,  globalGEPV, "", b);
            Type    *ty = Type::getInt64Ty(b->getContext());
            Value   *intVal = new PtrToIntInst(globalGEP, ty, "", b);
            uint32_t addr_offset = disp-baseGlobal;
            Value   *int_adjusted = 
                BinaryOperator::CreateAdd(intVal, CONST_V<64>(b, addr_offset), "", b);
            //then, assign this to the outer 'd' so that the rest of the 
            //logic picks up on that address instead of another address 
            d = int_adjusted;
        } 
    } else {

        //there is no disp value, or its relative to esp/ebp in which case
        //we might not want to do anything
    }

    if( d == NULL ) {
        //create a constant integer out of the raw displacement
        //we were unable to assign the displacement to an address
        d = ConstantInt::getSigned(iTy, disp);
    }

    Value   *rVal = NULL;

    //read the base register (if given)
    if( baseReg != X86::NoRegister && baseReg != X86::RIP) {
        rVal = R_READ<64>(b, baseReg);
    } else {
        //if the base is not present, just use 0
        rVal = CONST_V<64>(b, 0);
    }


    Value   *dispComp;
    dispComp = 
        BinaryOperator::Create( Instruction::Add, rVal, d, "", b);

    //add the index amount, if present
	if( Oindex.getReg() != X86::NoRegister ) {
		Value       *index = R_READ<64>(b, Oindex.getReg());
        
        int64_t scaleAmt = Oscale.getImm();
        if( scaleAmt > 1 ) {
            index = 
                BinaryOperator::CreateMul(index,CONST_V<64>(b, scaleAmt),"",b);
        }

		dispComp = 
			BinaryOperator::CreateAdd(dispComp, index, "", b);
        
    }

    //convert the resulting integer into a pointer type
    PointerType *piTy = Type::getInt64PtrTy(b->getContext());
    Value       *dispPtr = new IntToPtrInst(dispComp, piTy, "", b);
    
    return dispPtr;
}

}
