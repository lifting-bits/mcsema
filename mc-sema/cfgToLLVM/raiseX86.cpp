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
#include "x86Instrs.h"
#include "x86Helpers.h"
#include "ArchOps.h"

#include <llvm/Object/COFF.h>
#include <llvm/IR/Constants.h>
#include <llvm/ADT/StringSwitch.h>
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/LinkAllPasses.h"


#include "llvm/IR/Type.h"
#include "llvm/IR/Metadata.h"
#include "postPasses.h"
#include <boost/graph/breadth_first_search.hpp>
#include "Externals.h"
#include "../common/to_string.h"
#include "../common/Defaults.h"

#include <vector>
#include <llvm/IR/InlineAsm.h>

using namespace llvm;
using namespace std;

bool ignoreUnsupportedInsts = false;


CallingConv::ID getLLVMCC(ExternalCodeRef::CallingConvention cc) {
    switch(cc) {
        case ExternalCodeRef::CallerCleanup:
            return CallingConv::C;
        case ExternalCodeRef::CalleeCleanup:
            return CallingConv::X86_StdCall;
        case ExternalCodeRef::FastCall:
            return CallingConv::X86_FastCall;
        default:
            throw TErr(__LINE__, __FILE__, 
                    "Unknown calling convention!");
            break;
    }

    return CallingConv::C;
}


void M_WRITE_T(InstPtr ip, llvm::BasicBlock *b, llvm::Value *addr, llvm::Value *data, llvm::Type *ptrtype) {
    //this is also straightforward
    llvm::Value   *writeLoc = addr;
    unsigned addrspace = ip->get_addr_space();
    //however, if the incoming 'addr' location is not a pointer, we must
    //first turn it into an addr 

    if( addr->getType()->isPointerTy() == false ) {
        writeLoc = new llvm::IntToPtrInst(addr, ptrtype, "", b); 
	} else if( addr->getType() != ptrtype ) {
		writeLoc = llvm::CastInst::CreatePointerCast(addr, ptrtype, "", b);
	}

    llvm::Value   *written = new llvm::StoreInst(data, writeLoc, b);
    TASSERT(written != NULL, "Failed to create StoreInst");

    return;
}

int mapPlatRegToOffset(unsigned reg) {
    switch(reg) {
        case X86::DH:
        case X86::CH:
        case X86::BH:
        case X86::AH:
            return 8;
            break;
        case X86::AX:
        case X86::AL:
        case X86::EAX:
        case X86::BX:
        case X86::BL:
        case X86::EBX:
        case X86::CX:
        case X86::CL:
        case X86::ECX:
        case X86::DX:
        case X86::DL:
        case X86::EDX:
        case X86::SI:
        case X86::ESI:
        case X86::DI:
        case X86::EDI:
        case X86::SP:
        case X86::ESP:
        case X86::BP:
        case X86::EBP:

        case X86::ST0:
        case X86::ST1:
        case X86::ST2:
        case X86::ST3:
        case X86::ST4:
        case X86::ST5:
        case X86::ST6:
        case X86::ST7:

        case X86::XMM0:
        case X86::XMM1:
        case X86::XMM2:
        case X86::XMM3:
        case X86::XMM4:
        case X86::XMM5:
        case X86::XMM6:
        case X86::XMM7:
            return 0;
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Reg type "+to_string<unsigned>(reg, dec)+" is unknown");
    }
    
    return -1;
}

string mapPlatRegToStr(unsigned reg) {
    //UPDATEREGS
    switch(reg) {
        case X86::AX:
        case X86::AH:
        case X86::AL:
        case X86::EAX:
            return "EAX";
            break;
        case X86::BX:
        case X86::BH:
        case X86::BL:
        case X86::EBX:
            return "EBX";
            break;
        case X86::CX:
        case X86::CH:
        case X86::CL:
        case X86::ECX:
            return "ECX";
            break;
        case X86::DX:
        case X86::DH:
        case X86::DL:
        case X86::EDX:
            return "EDX";
            break;
        case X86::SI:
        case X86::ESI:
            return "ESI";
            break;
        case X86::DI:
        case X86::EDI:
            return "EDI";
            break;
        case X86::SP:
        case X86::ESP:
            return "ESP";
            break;
        case X86::BP:
        case X86::EBP:
            return "EBP";
            break;
        case X86::ST0:
            return "ST0";
            break;
        case X86::ST1:
            return "ST1";
            break;
        case X86::ST2:
            return "ST2";
            break;
        case X86::ST3:
            return "ST3";
            break;
        case X86::ST4:
            return "ST4";
            break;
        case X86::ST5:
            return "ST5";
            break;
        case X86::ST6:
            return "ST6";
            break;
        case X86::ST7:
            return "ST7";
            break;
        case X86::XMM0:
            return "XMM0";
            break;
        case X86::XMM1:
            return "XMM1";
            break;
         case X86::XMM2:
            return "XMM2";
            break;
         case X86::XMM3:
            return "XMM3";
            break;
         case X86::XMM4:
            return "XMM4";
            break;
         case X86::XMM5:
            return "XMM5";
            break;
         case X86::XMM6:
            return "XMM6";
            break;
         case X86::XMM7:
            return "XMM7";
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Reg type "+to_string<unsigned>(reg, dec)+" is unknown");
            return "";
    }
}

int mapStrToFloatOff(std::string regName)
{
    int off = StringSwitch<int>(regName)
        .Case("ST0", 0) // NOT A MISTAKE. These
        .Case("ST1", 1) // are in a separate structure
        .Case("ST2", 2)
        .Case("ST3", 3)
        .Case("ST4", 4)
        .Case("ST5", 5)
        .Case("ST6", 6)
        .Case("ST7", 7)
        .Default(-1);
   
    if( off == -1 )
      throw  TErr(__LINE__, __FILE__, "Float reg name "+regName+" unknown");

    return off;
}

int mapStrToGEPOff(string regName) {
    int off = StringSwitch<int>(regName)
        //UPDATEREGS
        .Case("EAX", 0)
        .Case("EBX", 1)
        .Case("ECX", 2)
        .Case("EDX", 3)
        .Case("ESI", 4)
        .Case("EDI", 5)
        .Case("ESP", 6)
        .Case("EBP", 7)
        .Case("CF", 8)
        .Case("PF", 9)
        .Case("AF", 10)
        .Case("ZF", 11)
        .Case("SF", 12)
        .Case("OF", 13)
        .Case("DF", 14)
        .Case("ST0", 15) // NOT A MISTAKE. These
        .Case("ST1", 15) // are in a separate structure
        .Case("ST2", 15)
        .Case("ST3", 15)
        .Case("ST4", 15)
        .Case("ST5", 15)
        .Case("ST6", 15)
        .Case("ST7", 15)
        .Case("FPU_B",  16)
        .Case("FPU_C3", 17)
        .Case("FPU_TOP",18)
        .Case("FPU_C2", 19)
        .Case("FPU_C1", 20)
        .Case("FPU_C0", 21)
        .Case("FPU_ES", 22)
        .Case("FPU_SF", 23)
        .Case("FPU_PE", 24)
        .Case("FPU_UE", 25)
        .Case("FPU_OE", 26)
        .Case("FPU_ZE", 27)
        .Case("FPU_DE", 28)
        .Case("FPU_IE", 29)
        .Case("FPU_X" ,  30)
        .Case("FPU_RC", 31)
        .Case("FPU_PC", 32)
        .Case("FPU_PM", 33)
        .Case("FPU_UM", 34)
        .Case("FPU_OM", 35)
        .Case("FPU_ZM", 36)
        .Case("FPU_DM", 37)
        .Case("FPU_IM", 38)
        .Case("FPU_TAG", 39)
		.Case("FPU_LASTIP_SEG", 40)
		.Case("FPU_LASTIP_OFF", 41)
		.Case("FPU_LASTDATA_SEG", 42)
		.Case("FPU_LASTDATA_OFF", 43)
		.Case("FPU_FOPCODE", 44)
		.Case("XMM0", 45)
		.Case("XMM1", 46)
		.Case("XMM2", 47)
		.Case("XMM3", 48)
		.Case("XMM4", 49)
		.Case("XMM5", 50)
		.Case("XMM6", 51)
		.Case("XMM7", 52)
		.Case("STACK_BASE", 53)
		.Case("STACK_LIMIT", 54)
        .Default(-1);
        
        
    if( off == -1 )
      throw  TErr(__LINE__, __FILE__, "Float reg name "+regName+" unknown");

    return off;
}

class bfs_cfg_visitor : public boost::default_bfs_visitor {
private:
    NativeFunctionPtr   natFun;
    Function            *F;
    NativeModulePtr     natMod;
    bool                &didError;
public:
    bfs_cfg_visitor(NativeFunctionPtr n, NativeModulePtr m, Function *F_, bool &e) : 
        natFun(n), F(F_),natMod(m),didError(e) { }
    template < typename Vertex, typename Graph >
    void discover_vertex(Vertex u, const Graph & g) const;
};

Value *lookupLocalByName(Function *F, string localName) {
    BasicBlock  *entry = &F->getEntryBlock();
    BasicBlock::iterator    it = entry->begin(); 

    while(it != entry->end() ) {
        Value   *v = it;
        
        if( v->getName() == localName ) {
            return v;
        }

        ++it;
    }
    
    
    throw TErr (__LINE__, __FILE__, "localname: "+localName+" is not found");
    return NULL;
}

Value *MCRegToValue(BasicBlock *b, unsigned reg) {
    string      regValName = mapPlatRegToStr(reg);
    Function    *F = b->getParent();

    return lookupLocalByName(F, regValName+"_val");
}

Value *GENERIC_READREG(BasicBlock *b, string regname) {
    Value       *localRegVar = lookupLocalByName(b->getParent(), regname+"_val");
    Instruction *readFlag = new LoadInst(localRegVar, "", b);
    return readFlag;
}

Value *F_READ(BasicBlock *b, string flag) {
    return GENERIC_READREG(b, flag);
}

void GENERIC_WRITEREG(BasicBlock *b, string regname, Value *v) {
    Value   *localRegVar = lookupLocalByName(b->getParent(), regname+"_val");
    if(localRegVar == NULL)
      throw TErr(__LINE__, __FILE__, "regname "+regname+" not found");
    Value   *st = new StoreInst(v, localRegVar, b);
    TASSERT(st != NULL, "");
    return;
}

void F_WRITE(BasicBlock *b, string flag, Value *v) {
    return GENERIC_WRITEREG(b, flag, v);
}

void F_ZAP(BasicBlock *b, string flag) { 
    F_WRITE(b, flag, UndefValue::get(Type::getInt1Ty(b->getContext())));
    return;
}

void F_SET(BasicBlock *b, string flag) {
    F_WRITE(b, flag, CONST_V<1>(b, 1));
    return;
}

void F_CLEAR(BasicBlock *b, string flag) {
    F_WRITE(b, flag, CONST_V<1>(b, 0));
    return;
}

//
// common case for arithmetic instructions
// some instructions, like inc and dec, do not need to do this 
//

void allocateLocals(Function *F, int bits) {
    //always at the beginning of a function
    //we need to allocate local variables via alloca, these locals will
    //live for the life of the function context and be the sources/sinks
    //of any activity involving registers or flags
    BasicBlock  *begin = &F->getEntryBlock();
    switch(bits) {
        case 32:
        {
            //UPDATEREGS -- when we add something to 'regs' struct change here
            //create a local for every member in the 'regs' struct
            //create 32-bit width general purpose registers
            Type    *uintTy = Type::getInt32Ty(F->getContext());
            Instruction *eaxA = new AllocaInst(uintTy, "EAX_val", begin);
            Instruction *ebxA = new AllocaInst(uintTy, "EBX_val", eaxA);
            Instruction *ecxA = new AllocaInst(uintTy, "ECX_val", ebxA);
            Instruction *edxA = new AllocaInst(uintTy, "EDX_val", ecxA);
            Instruction *esiA = new AllocaInst(uintTy, "ESI_val", edxA);
            Instruction *ediA = new AllocaInst(uintTy, "EDI_val", esiA);
            Instruction *ebpA = new AllocaInst(uintTy, "EBP_val", ediA);
            Instruction *espA = new AllocaInst(uintTy, "ESP_val", ebpA);
            //create other fields for flags
            
            Type    *boolTy = Type::getInt1Ty(F->getContext());
            Instruction *zfA = new AllocaInst(boolTy, "ZF_val", espA);
            Instruction *sfA = new AllocaInst(boolTy, "PF_val", zfA);
            Instruction *ofA = new AllocaInst(boolTy, "AF_val", sfA);
            Instruction *cfA = new AllocaInst(boolTy, "CF_val", ofA);
            Instruction *pfA = new AllocaInst(boolTy, "SF_val", cfA);
            Instruction *afA = new AllocaInst(boolTy, "OF_val", pfA);
			      Instruction *dfA = new AllocaInst(boolTy, "DF_val", afA);
            TASSERT(dfA != NULL, "");

            // FPU STACK
            Type    *floatTy = Type::getX86_FP80Ty(F->getContext());
            // 8 float values make up the ST registers
            Type    *floatArrayTy = ArrayType::get(floatTy, 8);
            Instruction *stRegs = new AllocaInst(floatArrayTy, "STi_val", dfA);

            // sanity check
            TASSERT(stRegs != NULL, "");

            // FPU FLAGS
            Instruction *fpu_B = new AllocaInst(boolTy,  "FPU_B_val", stRegs);
            Instruction *fpu_C3 = new AllocaInst(boolTy, "FPU_C3_val", fpu_B);

            // TOP of stack from FPU flags
            // really a 3-bit integer
            Type    *topTy = Type::getIntNTy(F->getContext(), 3);
            Instruction *fpu_TOP = new AllocaInst(topTy, "FPU_TOP_val", fpu_C3);
            TASSERT(fpu_TOP != NULL, "");

            Instruction *fpu_C2 = new AllocaInst(boolTy, "FPU_C2_val", fpu_TOP);
            Instruction *fpu_C1 = new AllocaInst(boolTy, "FPU_C1_val", fpu_C2);
            Instruction *fpu_C0 = new AllocaInst(boolTy, "FPU_C0_val", fpu_C1);
            Instruction *fpu_ES = new AllocaInst(boolTy, "FPU_ES_val", fpu_C0);
            Instruction *fpu_SF = new AllocaInst(boolTy, "FPU_SF_val", fpu_ES);
            Instruction *fpu_PE = new AllocaInst(boolTy, "FPU_PE_val", fpu_SF);
            Instruction *fpu_UE = new AllocaInst(boolTy, "FPU_UE_val", fpu_PE);
            Instruction *fpu_OE = new AllocaInst(boolTy, "FPU_OE_val", fpu_UE);
            Instruction *fpu_ZE = new AllocaInst(boolTy, "FPU_ZE_val", fpu_OE);
            Instruction *fpu_DE = new AllocaInst(boolTy, "FPU_DE_val", fpu_ZE);
            Instruction *fpu_IE = new AllocaInst(boolTy, "FPU_IE_val", fpu_DE);

            // sanity check
            TASSERT(fpu_IE != NULL, "");

            // FPU CONTROL FLAGS
            Type    *int2Ty = Type::getIntNTy(F->getContext(), 2);
            Instruction *fpu_X =  new AllocaInst(boolTy, "FPU_X_val",  fpu_IE);
            Instruction *fpu_RC = new AllocaInst(int2Ty, "FPU_RC_val", fpu_X);
            Instruction *fpu_PC = new AllocaInst(int2Ty, "FPU_PC_val", fpu_RC);
            Instruction *fpu_PM = new AllocaInst(boolTy, "FPU_PM_val", fpu_PC);
            Instruction *fpu_UM = new AllocaInst(boolTy, "FPU_UM_val", fpu_PM);
            Instruction *fpu_OM = new AllocaInst(boolTy, "FPU_OM_val", fpu_UM);
            Instruction *fpu_ZM = new AllocaInst(boolTy, "FPU_ZM_val", fpu_OM);
            Instruction *fpu_DM = new AllocaInst(boolTy, "FPU_DM_val", fpu_ZM);
            Instruction *fpu_IM = new AllocaInst(boolTy, "FPU_IM_val", fpu_DM);

            TASSERT(fpu_IM != NULL, "");

            // FPU TAG WORD
            // 8 2-bit values. One for each ST register
            Type    *tagArrayType = ArrayType::get(int2Ty, 8);
            Instruction *fpu_TagWord = new AllocaInst(tagArrayType, "FPU_TAG_val", fpu_IM);

            TASSERT(fpu_TagWord != NULL, "");

            Instruction *fpu_LASTIP_SEG = new AllocaInst(Type::getInt16Ty(F->getContext()),   "FPU_LASTIP_SEG_val"  , fpu_TagWord);
            Instruction *fpu_LASTIP_OFF = new AllocaInst(Type::getInt32Ty(F->getContext()),   "FPU_LASTIP_OFF_val"  , fpu_LASTIP_SEG);
            Instruction *fpu_LASTDATA_SEG = new AllocaInst(Type::getInt16Ty(F->getContext()), "FPU_LASTDATA_SEG_val", fpu_LASTIP_OFF);
            Instruction *fpu_LASTDATA_OFF = new AllocaInst(Type::getInt32Ty(F->getContext()), "FPU_LASTDATA_OFF_val", fpu_LASTDATA_SEG);

            Instruction *fpu_FOPCODE = new AllocaInst(Type::getIntNTy(F->getContext(), 11), "FPU_FOPCODE_val", fpu_LASTDATA_OFF);
            TASSERT(fpu_FOPCODE != NULL, "");

            //vector registers
            Instruction *vec_xmm0 = 
                new AllocaInst( Type::getIntNTy(F->getContext(), 128),
                                "XMM0_val",
                                fpu_FOPCODE); 
            Instruction *vec_xmm1 = 
                new AllocaInst( Type::getIntNTy(F->getContext(), 128),
                                "XMM1_val",
                                vec_xmm0); 
            Instruction *vec_xmm2 = 
                new AllocaInst( Type::getIntNTy(F->getContext(), 128),
                                "XMM2_val",
                                vec_xmm1);
            Instruction *vec_xmm3 = 
                new AllocaInst( Type::getIntNTy(F->getContext(), 128),
                                "XMM3_val",
                                vec_xmm2);
            Instruction *vec_xmm4 = 
                new AllocaInst( Type::getIntNTy(F->getContext(), 128),
                                "XMM4_val",
                                vec_xmm3);
            Instruction *vec_xmm5 = 
                new AllocaInst( Type::getIntNTy(F->getContext(), 128),
                                "XMM5_val",
                                vec_xmm4);
            Instruction *vec_xmm6 = 
                new AllocaInst( Type::getIntNTy(F->getContext(), 128),
                                "XMM6_val",
                                vec_xmm5);
            Instruction *vec_xmm7 = 
                new AllocaInst( Type::getIntNTy(F->getContext(), 128),
                                "XMM7_val",
                                vec_xmm6);

            // stack base and limit
            Instruction *stack_base = 
                new AllocaInst( Type::getInt32Ty(F->getContext()),
                                "STACK_BASE_val",
                                vec_xmm7);
            Instruction *stack_limit = 
                new AllocaInst( Type::getInt32Ty(F->getContext()),
                                "STACK_LIMIT_val",
                                stack_base);
        }
            break;

        case 64:
            throw TErr(__LINE__, __FILE__, "64-bit not supported yet");
            break;

        default:
            throw TErr(__LINE__, __FILE__, "Unsupported bitwidth "+to_string<int>(bits, dec));
    }

    return;
}

BasicBlock *bbFromStrName(string n, Function *F) {
    BasicBlock  *found = NULL;

    for( Function::iterator it = F->begin(); it != F->end(); ++it ) {
        BasicBlock  *b = it;
        
        if( b->getName() == n ) {
            found = b;
            break;
        }
    }

    return found;
}


InstTransResult disInstr(   InstPtr             ip, 
                            BasicBlock          *&block, 
                            NativeBlockPtr      nb,
                            Function            *F,
                            NativeFunctionPtr   natF,
                            NativeModulePtr     natM) 
{

    size_t bsize_pre = block->size();

    //add a string representation of this instruction to the CFG
    //this string representation should be removed by optimizations
    
    //in the future, we could have different target decoders here
    InstTransResult disInst_result = disInstrX86(ip, block, nb, F, natF, natM);

    return disInst_result; 
}

template <typename Vertex, typename Graph>
void bfs_cfg_visitor::discover_vertex(Vertex u, const Graph &g) const {
    NativeBlockPtr  curBlock = this->natFun->block_from_id(u);
    BasicBlock      *curLLVMBlock = NULL;
  
    if( curBlock == NULL )
      throw TErr(__LINE__, __FILE__, "Could not look up block "+to_string<Vertex>(u, dec));

    //first, either create or look up the LLVM basic block for this native 
    //block. we are either creating it for the first time, or, we are 
    //going to look up a blank block
    curLLVMBlock = bbFromStrName(curBlock->get_name(), this->F);

    if( curLLVMBlock == NULL ) {
        //we need to create the block, so do that 
        curLLVMBlock = BasicBlock::Create(  this->F->getContext(),
                                            curBlock->get_name(),
                                            this->F);
        TASSERT(curLLVMBlock != NULL, "" );
    }

    //then, create a basic block for every follow of this block, if we do not
    //already have that basic block in our LLVM CFG
    list<VA>    &follows = curBlock->get_follows();
    for(list<VA>::iterator i = follows.begin(); i != follows.end(); ++i) {
        VA      blockBase = *i;
        //try and look up a block that has this blocks name
        NativeBlockPtr followNat = this->natFun->block_from_base(blockBase);
        string followName = followNat->get_name();
        
        BasicBlock  *fBB = bbFromStrName(followName, this->F);

        if( fBB == NULL ) {
            fBB = BasicBlock::Create(  this->F->getContext(),
                                                followNat->get_name(),
                                                this->F);
            TASSERT(fBB != NULL, "" );
        }
    }

    //now, go through each statement and translate it into LLVM IR
    //statements that branch SHOULD be the last statement in a block
    list<InstPtr>   stmts = curBlock->get_insts();
    
    for( list<InstPtr>::iterator it = stmts.begin(); it != stmts.end(); ++it) {
        InstPtr inst = *it;

        InstTransResult r = 
            disInstr(inst, curLLVMBlock, curBlock, this->F, this->natFun, this->natMod);

        if( r == TranslateError ) {
            this->didError = true;
            break;
        }
        if( r == TranslateErrorUnsupported && ignoreUnsupportedInsts == false ) {
            this->didError = true;
            break;
        }
    }

    return;
}

static bool insertFunctionIntoModule(NativeModulePtr mod, NativeFunctionPtr func, Module *M) {
    //okay, now we traverse the graph and add the instructions and blocks
    //into the llvm module

    //first, get the LLVM function for this native function
    Function        *F = M->getFunction(func->get_name());

    if( F == NULL )
      throw TErr(__LINE__, __FILE__, "Could not get func "+func->get_name());
    //
    if ( F->empty() == false )
    {
        cout << "WARNING: Asking to re-insert function: " << func->get_name() << std::endl;
        cout << "\tReturning current function instead" << std::endl;
        return true;
    }

    
    //create the entry block for the function
    //this block will alloca cells on the 'stack' for every register in the 
    //register member structure 
    BasicBlock  *entryBlock = BasicBlock::Create(   F->getContext(),
                                                    "entry", 
                                                    F);
    TASSERT(entryBlock != NULL, "" );

    allocateLocals(F, 32);
    //and at the beginning of the function, we spill all the context
    writeContextToLocals(entryBlock, 32);

    //then we put an unconditional branch from the 'entry' block to the first
    //block, and we create the first block
    NativeBlockPtr  funcEntry = func->block_from_base(func->get_start());
    BasicBlock      *firstBlock = BasicBlock::Create(   F->getContext(),
                                                        funcEntry->get_name(),
                                                        F);
    TASSERT( firstBlock != NULL, "" );
    //create a branch from the end of the entry block to the first block
    BranchInst::Create(firstBlock, entryBlock);

    //now, start crawling everything in NativeFunctionPtr
    CFG             funcGraph = func->get_cfg();
    bool            error = false;
    bfs_cfg_visitor v(func, mod, F, error);

    //visit every vertex in the graph, starting from the entry block, which
    //always should be block 0
    //this traversal wil build us the LLVM graph from the native graph
    boost::breadth_first_search(funcGraph, 
                                boost::vertex(func->entry_block_id(), funcGraph), 
                                boost::visitor(v));

    //check that the function we created is valid

    //we should be done, having inserted every block into the module
    if( error ) {
        return false;
    } else {
        return true;
    }
}

bool doPostAnalysis(NativeModulePtr N, Module *M) {
  //first, we need to instantiate the pass manager and perform the mem2reg transform
  //on the module to lift it at least into SSA form
  PassManager         modulePasses;
  FunctionPassManager functionPasses(M);
  PassManagerBuilder  builder;

  builder.OptLevel = 1;
  builder.SizeLevel = 0;

  //register our specific analyses
  registerPostPasses(builder);

  builder.populateModulePassManager(modulePasses);
  builder.populateFunctionPassManager(functionPasses);

  functionPasses.doInitialization();
  for(Module::iterator i = M->begin(), e = M->end(); i != e; ++i) {
    functionPasses.run(*i);
  }
  functionPasses.doFinalization();

  modulePasses.run(*M);

  return true;
}


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
        ci->setCallingConv(CallingConv::X86_StdCall);
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
        ExternalCodeRef::CallingConvention cconv) 
{
  //convert the VA into a string name of a function, try and look it up
  string  s("sub_"+to_string<VA>(entry, hex));
  Function  *F = M->getFunction(s);
  Type *int32ty = Type::getInt32Ty(M->getContext());
  Type *int32PtrTy = PointerType::get(int32ty, 0);

  if( F != NULL ) {
    //build function prototype from name and numParms
    vector<Type *>  args;

    for(int i = 0; i < np; i++) {
      args.push_back(Type::getInt32Ty(M->getContext()));
    }

    Type  *returnTy = NULL;
    if(ret) {
      returnTy = Type::getInt32Ty(M->getContext());
    } else{
      returnTy = Type::getVoidTy(M->getContext());
    }

    FunctionType *FT = FunctionType::get(returnTy, args, false);

    //insert the function prototype
    Function  *driverF = (Function *) M->getOrInsertFunction(name, FT); 
    // set drivers calling convention to match user specification
    driverF->setCallingConv(getLLVMCC(cconv));

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

    if (cconv == ExternalCodeRef::FastCall) 
    {
        // make __fastcall functions work:
        // set ecx to arg[0]
        if(fwd_it != fwd_end) {

            int   k = mapStrToGEPOff("ECX");
            Value *ecxFieldGEPV[] = {
                CONST_V<32>(driverBB, 0),
                CONST_V<32>(driverBB, k)
            };

            // make driver take this from register
            fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 1, B));

            Value *ecxP = 
                GetElementPtrInst::CreateInBounds(aCtx, ecxFieldGEPV, "", driverBB);
            Argument  *curArg = &(*fwd_it);
            new StoreInst(curArg, ecxP, driverBB);
        }
        // make __fastcall functions work:
        // set edx to arg[1]
        ++fwd_it;
        if(fwd_it != fwd_end) {
            int   k = mapStrToGEPOff("EDX");
            Value *edxFieldGEPV[] = {
                CONST_V<32>(driverBB, 0),
                CONST_V<32>(driverBB, k)
            };

            // make driver take this from register
            fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 2, B));

            Value *edxP = 
                GetElementPtrInst::CreateInBounds(aCtx, edxFieldGEPV, "", driverBB);
            

            Argument  *curArg = &(*fwd_it);
            new StoreInst(curArg, edxP, driverBB);
        }
    } // fastcall

    //write the parameters into the stack 
    Function::ArgumentListType::reverse_iterator  it = 
      driverF->getArgumentList().rbegin();
    Function::ArgumentListType::reverse_iterator  end = 
      driverF->getArgumentList().rend();

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
                    stackPosInt, CONST_V<32>(driverBB, 4*12), "", driverBB);

    // decrement stackPtr once to have a slot for
    // "return address", even if there are no arguments
    stackPosInt = BinaryOperator::Create(BinaryOperator::Sub,
                    stackPosInt, CONST_V<32>(driverBB, 4), "", driverBB);

    int args_to_push = driverF->getArgumentList().size();
    if(cconv == ExternalCodeRef::FastCall) {
        // these are already in registers
        args_to_push -= 2;
        if (args_to_push < 0) {
            args_to_push = 0;
        }
    }

    // save arguments on the stack
    while(args_to_push > 0)
    {
      Argument  *curArg = &(*it);
      // convert to int32 ptr
      Value *stackPosPtr = new IntToPtrInst(stackPosInt, int32PtrTy, "", driverBB );
      // write argument
      Value *k = new StoreInst(curArg, stackPosPtr, driverBB);
      // decrement stack
      stackPosInt = BinaryOperator::Create(BinaryOperator::Sub,
                stackPosInt, CONST_V<32>(driverBB, 4), "", driverBB);
      ++it;
      --args_to_push;
    }

    int   k = mapStrToGEPOff("ESP");
    Value *spFieldGEPV[] = {
      CONST_V<32>(driverBB, 0),
      CONST_V<32>(driverBB, k)
    };
    k = mapStrToGEPOff("STACK_BASE");
    Value *stackBaseGEPV[] = {
      CONST_V<32>(driverBB, 0),
      CONST_V<32>(driverBB, k)
    };
    k = mapStrToGEPOff("STACK_LIMIT");
    Value *stackLimitGEPV[] = {
      CONST_V<32>(driverBB, 0),
      CONST_V<32>(driverBB, k)
    };

    Value *spValP = 
      GetElementPtrInst::CreateInBounds(aCtx, spFieldGEPV, "", driverBB);

    Value *sBaseValP = 
      GetElementPtrInst::CreateInBounds(aCtx, stackBaseGEPV, "", driverBB);

    Value *sLimitValP = 
      GetElementPtrInst::CreateInBounds(aCtx, stackLimitGEPV, "", driverBB);

    // stack limit = start of allocation (stack grows down);
    new StoreInst(aStack, sLimitValP, driverBB);
    // stack base = stack alloc start + stack size
    new StoreInst(stackBaseInt, sBaseValP, driverBB);

    // all functions assume DF is clear on entry
    k = mapStrToGEPOff("DF");
    Value *dflagGEPV[] = {
      CONST_V<32>(driverBB, 0),
      CONST_V<32>(driverBB, k)
    };

    Value *dflagP = 
      GetElementPtrInst::CreateInBounds(aCtx, dflagGEPV, "", driverBB);

    new StoreInst(CONST_V<1>(driverBB, 0), dflagP, driverBB);


    Value *j = new StoreInst(stackPosInt, spValP, driverBB);
    TASSERT(j != NULL, "Could not write stack value to ESP");

    //call the sub function with register struct as argument
    vector<Value*>  subArg;

    subArg.push_back(aCtx);

    CallInst* ci = CallInst::Create(F, subArg, "", driverBB);
    ci->setCallingConv(CallingConv::X86_StdCall);

    archFreeStack(M, aStack, driverBB);

    //if we are requested, return the EAX value, else return void
    if(ret) {
      //do a GEP and load for the EAX register in the reg structure 
      int j = mapStrToGEPOff("EAX");
      Value *eaxGEPV[] = {
        CONST_V<32>(driverBB, 0), 
        CONST_V<32>(driverBB, j)
      };

      Value *eaxVP = 
        GetElementPtrInst::CreateInBounds(aCtx, eaxGEPV, "", driverBB);
      Value *eaxV = new LoadInst(eaxVP, "", driverBB);

      //return that value 
      ReturnInst::Create(driverF->getContext(), eaxV, driverBB);
    } else {
      ReturnInst::Create(driverF->getContext(), driverBB);
    }

  } else {
      report << "Could not find entry point function\n";
    return false;
  }

  return true;
}

static Constant* makeConstantBlob(LLVMContext &ctx, const vector<uint8_t> &blob) {

    Type        *charTy = Type::getInt8Ty(ctx);
    ArrayType   *arrT = ArrayType::get(charTy, blob.size());
    vector<uint8_t>::const_iterator     it = blob.begin();
    vector<Constant*> array_elements;
    while( it != blob.end() ) {
        uint8_t     cur = *it; 
        IntegerType *ty = Type::getInt8Ty(ctx);
        Constant    *c = ConstantInt::get(ty, cur);

        array_elements.push_back(c);
        ++it;
    }

    return ConstantArray::get(arrT, array_elements);
}

static GlobalVariable* getSectionForDataAddr(
        const list<DataSection>  &dataSecs, 
        Module *M, 
        VA data_addr, 
        VA &section_base)
{
    
    for(list<DataSection>::const_iterator git = dataSecs.begin();
        git != dataSecs.end();
        git++)
    {
        const DataSection         &dt = *git;
        VA start = dt.getBase();
        VA end = start+dt.getSize();

        if(data_addr >= start && data_addr < end) {
            std::string gvar_name = "data_0x" + to_string<VA>(start, hex);//+"_ptr";
            section_base = start;
     
        }
        
    }

    return NULL;

}

void dataSectionToTypesContents(
        const list<DataSection>  &globaldata, 
        DataSection& ds, 
        Module *M,
        vector<Constant*>&    secContents,
        vector<Type*>& data_section_types,
        bool convert_to_callback) 
{
    // find what elements will be needed for this data section
    // There are three main types:
    // Functions: pointer to a known function in the cfg
    // Data Symbol: pointer to another data section item
    // Blob: opaque data treated as byte array
    //
    // The final data structure will look something like
    // struct data_section {
    //  function f1,
    //  function f2,
    //  uint8_t blob0[100];
    //  datasymbol d0;
    //  uint8_t blob1[200];
    //  ....
    //  };
    //
    const std::list<DataSectionEntry> &ds_entries = ds.getEntries();
    for(list<DataSectionEntry>::const_iterator dsec_itr = ds_entries.begin();
            dsec_itr != ds_entries.end();
            dsec_itr++)
    {
        string sym_name;
        if(dsec_itr->getSymbol(sym_name)) {
            const char *func_addr_str = sym_name.c_str()+4;
            VA func_addr = strtol(func_addr_str, NULL, 16);

            if(sym_name.find("sub_") == 0) {
                // add function pointer to data section
                // to do this, create a callback driver for
                // it first (since it may be called externally)

                Function *func = NULL;

                if(convert_to_callback) {
                    func = dynamic_cast<Function*>
                        (archMakeCallbackForLocalFunction(M, func_addr));
                    TASSERT(func != NULL, "Could make callback for: "+sym_name);
                } else {
                    func = M->getFunction(sym_name);
                    TASSERT(func != NULL, "Could not find function: "+sym_name);
                }

                secContents.push_back(func);
                data_section_types.push_back(func->getType());
            } else {
                // data symbol
                // get the base of the data section for this symobol
                // then compute the offset from base of data 
                // and store as integer value of (base+offset)
                VA section_base;
                GlobalVariable *g_ref = getSectionForDataAddr(
                        globaldata, 
                        M, 
                        func_addr, 
                        section_base);
                TASSERT(g_ref != NULL, "Could not get data addr for:"+string(func_addr_str));
                // instead of referencing an element directly
                // we just convert the pointer to an integer
                // and add its offset from the base of data
                // to the new data section pointer
                VA addr_diff = func_addr - section_base;

                Constant *int_val = ConstantExpr::getPtrToInt(g_ref,
                        Type::getInt32Ty(M->getContext()) );
                Constant *final_val = ConstantExpr::getAdd(
                        int_val, CONST_V_INT<32>(M->getContext(), addr_diff));
                secContents.push_back(final_val);
                data_section_types.push_back(final_val->getType());
            }
        } else {
            // add array
            // this holds opaque data in a byte array
            Constant *arr = 
                makeConstantBlob(M->getContext(), dsec_itr->getBytes());
            secContents.push_back(arr);
            data_section_types.push_back(arr->getType());
        } // if dsec_itr
    } // for list
}

static bool insertDataSections(NativeModulePtr natMod, Module *M, raw_ostream &report) {

    list<DataSection>  &globaldata = natMod->getData();
    list<DataSection>::iterator git = globaldata.begin();

    //insert all global data before we insert the CFG

    vector<pair<StructType*,GlobalVariable*> > gvars;

    // pre-create references to all data sections
    // as later we may have data references that are
    // from one section into another
    
    while( git != globaldata.end() ) {
        DataSection         &dt = *git;
        string          bufferName;
        bufferName = "data_0x" + to_string<VA>(dt.getBase(), hex);
        //report << "inserting global data section named "; 
        //report << bufferName << "\n";
        std::cout << "inserting global data section named "; 
        std::cout << bufferName << std::endl;

        StructType *st_opaque = StructType::create(M->getContext());
        GlobalVariable *g = new GlobalVariable(*M,
                                st_opaque, 
                                dt.isReadOnly(),
                                // Used to be PrivateLinkage, but that emitted
                                // .objs that would not link with MSVC
                                GlobalVariable::InternalLinkage,
                                NULL,
                                bufferName);
        gvars.push_back(pair<StructType*,GlobalVariable*>(st_opaque, g));
        git++;
    }

    // actually populate the data sections
    git = globaldata.begin();
    vector<pair<StructType*,GlobalVariable*> >::const_iterator gvit = gvars.begin();
    while( git != globaldata.end() && gvit != gvars.end() ) {
        //data from the native module
        DataSection         &dt = *git;

        //data we use to create LLVM values for this section
        // secContents is the actual values we will be inserting
        vector<Constant*>    secContents;
        // data_section_types is their types, which are needed to initialize
        // the global variable 
        vector<Type*> data_section_types;



        // create an opaque structure so we can create an opaque global
        // variable.
        // The opaque variable currently serves as a base for self-
        // referential data. 
        StructType *st_opaque = gvit->first;
        GlobalVariable *g = gvit->second;


        dataSectionToTypesContents(
                globaldata, 
                dt, 
                M, 
                secContents, 
                data_section_types, 
                true);

        // fill in the opaqure structure with actual members
        st_opaque->setBody(data_section_types, true);

        // create an initializer list using the now filled in opaque
        // structure type
        Constant *cst = ConstantStruct::get(st_opaque, secContents);
        // byte aligned since we are not sure what kind of pointer arithmetic
        // has taken place
        g->setAlignment(1);
        g->setInitializer(cst);

        git++;
        gvit++;

    } // while git != globaldata.end()

    return true;

}

bool natModToModule(NativeModulePtr natMod, Module *M, raw_ostream &report) {
    bool    result = true;

    //iterate over every functions CFG we identified in natMod
    list<NativeFunctionPtr> funcs = natMod->get_funcs();
    list<NativeFunctionPtr>::iterator   i = funcs.begin();

    // insert all functions (but not populate yet)
    while( i != funcs.end() ) {
        NativeFunctionPtr   f = *i;
        std::string fname = f->get_name();

        Function *F = M->getFunction(fname);

        if(F == NULL) { 
            Constant *FC = M->getOrInsertFunction(fname, getBaseFunctionType(M));
            F = dyn_cast<Function>(FC);

            TASSERT(F != NULL, "Could not insert function into module");

            // default to stdcall
            F->setCallingConv(CallingConv::X86_StdCall);
            // make local functions 'static'
            F->setLinkage(GlobalValue::InternalLinkage);
            cout << "Inserted function: " << fname << std::endl;
        } else {
            cout << "Already inserted function: " << fname << ", skipping." << std::endl;
        }

        ++i;
    }


    // insert data after functions -- data may have function references
    insertDataSections(natMod, M, report);

    list<ExternalDataRefPtr> extDataRefs = natMod->getExtDataRefs();
    list<ExternalDataRefPtr>::iterator data_it = extDataRefs.begin();

    for( ; data_it != extDataRefs.end(); ++data_it ) {
        ExternalDataRefPtr   dr = *data_it;
        int dsize = dr->getDataSize();
        std::string symname = dr->getSymbolName();
        if (dsize > 16) {
            throw TErr(__LINE__, __FILE__,
                    "Unsupported external data size!");
        }

        // for now, just use integer types
        Type *extType = Type::getIntNTy(M->getContext(), dsize*8);

        GlobalValue *gv = dyn_cast<GlobalValue>(M->getOrInsertGlobal(symname, extType));
        TASSERT(gv != NULL, "Could not make global value!");
        gv->setLinkage(GlobalValue::AvailableExternallyLinkage);

        const std::string &triple = M->getTargetTriple();

        if(triple == WINDOWS_TRIPLE) {
            // this only makes sense for win32
            gv->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
        }
    }

    //iterate over the list of external functions and insert them as 
    //global functions
    list<ExternalCodeRefPtr> extCalls = natMod->getExtCalls();
    list<ExternalCodeRefPtr>::iterator it = extCalls.begin();
    for( ; it != extCalls.end(); ++it ) {
        ExternalCodeRefPtr   e = *it;
        
        ExternalCodeRef::CallingConvention   conv = e->getCallingConvention();
        int8_t                          argCount = e->getNumArgs();
        string                          symName = e->getSymbolName();

        //create the function if it is not already there
        Function    *f = M->getFunction(symName);
        if( f == NULL ) {
            vector<Type*>   arguments;
            Type            *returnType = NULL;

            //create arguments 
            for( int i = 0; i < argCount; i++ ) {
                arguments.push_back(Type::getInt32Ty(M->getContext()));
            }

            //create function type
            switch(e->getReturnType()) {
                case ExternalCodeRef::NoReturn:
                case ExternalCodeRef::VoidTy:
                    returnType = Type::getVoidTy(M->getContext());
                    break;

                case ExternalCodeRef::Unknown:
                case ExternalCodeRef::IntTy:
                    returnType = Type::getInt32Ty(M->getContext());
                    break;
                default:
                    throw TErr(__LINE__, __FILE__, 
                              "Encountered an unknown return type while translating function");
            }
            FunctionType    *ft = FunctionType::get(returnType,
                                                    arguments,
                                                    false);
            f = Function::Create(   ft, 
                GlobalValue::ExternalLinkage, 
                symName, 
                M);

            if(e->getReturnType() == ExternalCodeRef::NoReturn) {
                f->setDoesNotReturn();
            }

            //set calling convention
            f->setCallingConv(getLLVMCC(conv));
        }
    }

    // populate functions
    i = funcs.begin();
    while( i != funcs.end() ) {
        NativeFunctionPtr   f = *i;

        if( insertFunctionIntoModule(natMod, f, M) == false ) {
            result = false;
            break;
        }
        ++i;
    }

    return result;
}
