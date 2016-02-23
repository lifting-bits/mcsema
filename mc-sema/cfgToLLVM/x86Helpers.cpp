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
#include "Externals.h"
#include "X86.h"
#include "x86Helpers.h"
#include "../common/to_string.h"
#include "llvm/Support/Debug.h"

using namespace llvm;
using namespace std;
//using namespace x86;
// check if addr falls into a data section, and is at least minAddr.
// the minAddr check exists for times when we are not sure if an address
// is a data reference or an immediate value; in some cases data is mapped
// at 0x0 and determining this could be tricky

bool addrIsInData(VA addr, NativeModulePtr m, VA &base, VA minAddr = 0x0 ) {
    list<DataSection>  &sections = m->getData();
    list<DataSection>::iterator it = sections.begin();

    // sanity check:
    // assume no data references before minAddr.
    if (addr < minAddr) {
        return false;
    }

    if(sections.size() == 0) {
        llvm::dbgs() << __FUNCTION__ << ": WARNING: no data sections!\n";
        return false;
    }
    while( it != sections.end() ) {
        DataSection         &curSec = *it;
        VA          low = curSec.getBase();
        VA          high = low+curSec.getSize();

        if( addr >= low && addr < high ) {
            base = low;
            return true;
        }

        ++it;
    }

    return false;
}

// Compute a Value from a complex address expression
// such as [0x123456+eax*4]
// If the expression references global data, use
// that in the computation instead of assuming values
// are opaque immediates
namespace x86 {
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

    //first, we should ask, is disp an absolute reference to
    //some global symbol in the original source module?
    //if it is, we can replace its value with that of a pointer
    //to global data
    //HANDY HEURISTIC HACK
    //if the base register is the stack pointer or the frame 
    //pointer, then skip this part
    Value       *d = NULL;
    IntegerType *iTy = IntegerType::getInt32Ty(b->getContext());

    if( dataOffset ||  
        (mod && disp && baseReg != X86::EBP && baseReg!= X86::ESP) ) 
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
                {   ConstantInt::get(Type::getInt32Ty(b->getContext()), 0), 
                    ConstantInt::get(Type::getInt32Ty(b->getContext()), 0)};
            Instruction *globalGEP = 
                GetElementPtrInst::Create(gData,  globalGEPV, "", b);
            Type    *ty = Type::getInt32Ty(b->getContext());
            Value   *intVal = new PtrToIntInst(globalGEP, ty, "", b);
            uint32_t addr_offset = disp-baseGlobal;
            Value   *int_adjusted = 
                BinaryOperator::CreateAdd(intVal, CONST_V<32>(b, addr_offset), "", b);
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
    if( baseReg != X86::NoRegister ) {
        rVal = R_READ<32>(b, baseReg);
    } else {
        //if the base is not present, just use 0
        rVal = CONST_V<32>(b, 0);
    }

    Value   *dispComp;
    dispComp = 
        BinaryOperator::Create( Instruction::Add, rVal, d, "", b);

    //add the index amount, if present
	if( Oindex.getReg() != X86::NoRegister ) {
		Value       *index = R_READ<32>(b, Oindex.getReg());
        
        int64_t scaleAmt = Oscale.getImm();
        if( scaleAmt > 1 ) {
            index = 
                BinaryOperator::CreateMul(index,CONST_V<32>(b, scaleAmt),"",b);
        }

		dispComp = 
			BinaryOperator::CreateAdd(dispComp, index, "", b);
        
    }

    //convert the resulting integer into a pointer type
    PointerType *piTy = Type::getInt32PtrTy(b->getContext());
    Value       *dispPtr = new IntToPtrInst(dispComp, piTy, "", b);
    
    return dispPtr;
}
}


Value *getAddrFromExpr( BasicBlock      *b,
                        NativeModulePtr mod,
                        const MCInst &inst,
                        InstPtr ip,
                        uint32_t which)
{
    const MCOperand& base = inst.getOperand(     which   +0);
    const MCOperand& scale = inst.getOperand(    which   +1);
    const MCOperand& index = inst.getOperand(    which   +2);
    const MCOperand& disp = inst.getOperand(     which   +3);
    const MCOperand& seg = inst.getOperand(      which   +4);

    TASSERT(base.isReg(), "");
    TASSERT(scale.isImm(), "");
    TASSERT(index.isReg(), "");
    TASSERT(disp.isImm(), "");
    TASSERT(seg.isReg(), "");

    // determine if this instruction is using a memory reference
    // or if the displacement should be used at face value
    bool has_ref = ip->has_reference(Inst::MEMRef);
    int64_t real_disp = has_ref ? ip->get_reference(Inst::MEMRef) : disp.getImm();
	llvm::Module *M = b->getParent()->getParent();
	
	if(getPointerSize(M) == Pointer32) {

		return x86::getAddrFromExpr(b, 
				mod, 
				base, 
				scale,
				index, 
				real_disp, 
				seg,
				has_ref);
			
	} else {
		return x86_64::getAddrFromExpr(b, 
				mod, 
				base, 
				scale,
				index, 
				real_disp, 
				seg,
				has_ref);
	}


}

Value *MEM_AS_DATA_REF(BasicBlock *B, 
        NativeModulePtr natM, 
        const MCInst &inst, 
        InstPtr ip,
        uint32_t which)
{
    if(false == ip->has_mem_reference) {
        throw TErr(__LINE__, __FILE__, "Want to use MEM as data ref but have no MEM reference");
    }
    return getAddrFromExpr(B, natM, inst, ip, which);
}


Instruction*  callMemcpy(BasicBlock *B, Value *dest, Value *src, uint32_t size, 
        uint32_t align, bool isVolatile)
{
    Value *copySize = CONST_V<32>(B, size);
    // ALIGN: 4 byte alignment, i think
    Value *alignSize = CONST_V<32>(B, align);
    // VOLATILE: false
    Value *vIsVolatile = CONST_V<1>(B, isVolatile);

    Type    *Tys[] = { 
        dest->getType(),
        src->getType(),
        copySize->getType()};

    Module  *M = B->getParent()->getParent();

    Function        *doMemCpy = 
        Intrinsic::getDeclaration(M, Intrinsic::memcpy, Tys);

    Value *callArgs[] = { 
        dest, // DST
        src,  // SRC
        copySize,  // SIZE
        alignSize,  // ALIGN
        vIsVolatile  // VOLATILE
    };

    // actually call llvm.memcpy
    return CallInst::Create(doMemCpy, callArgs, "", B);
}
