/*
Copyright (c) 2014, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of Trail of Bits nor the names of its
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
#include <vector>
#include <unordered_set>
#include <string>
#include "peToCFG.h"
#include "JumpTables.h"
#include "toLLVM.h"
#include "raiseX86.h"

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include "../common/to_string.h"
#include "x86Helpers.h"
#include "InstructionDispatch.h"
#include "llvm/Support/Debug.h"

using namespace std;
using namespace llvm;
//using namespace x86;

extern llvm::PointerType *g_PRegStruct;

// convert a jump table to a data section of symbols
static DataSection* tableToDataSection(VA new_base, const MCSJumpTable& jt) {
    DataSection *ds = new DataSection();
    
    const vector<VA>& entries = jt.getJumpTable();
    VA curAddr = new_base;

    for(vector<VA>::const_iterator itr = entries.begin();
        itr != entries.end();
        itr++)
    {
        string sub_name = "sub_" + to_string<VA>(*itr, hex);
        DataSectionEntry dse(curAddr, sub_name);
        ds->addEntry(dse);
        curAddr += 4;
    }

    return ds;
}

// convert an index table to a data blob
static DataSection* tableToDataSection(VA new_base, const JumpIndexTable& jit) {
    DataSection *ds = new DataSection();
    
    const vector<uint8_t>& entries = jit.getJumpIndexTable();

    DataSectionEntry dse(new_base, entries);
    ds->addEntry(dse);

    return ds;
}

template <class T>
static bool addTableDataSection(NativeModulePtr natMod, 
        Module *M, VA &newVA, const T& table)
{

    list<DataSection>  &globaldata = natMod->getData();
    list<DataSection>::const_iterator git = globaldata.begin();

    // ensure we make this the last data section
    newVA = 0;
    while( git != globaldata.end() ) {
        const DataSection         &dt = *git;
        uint64_t extent = dt.getBase() + dt.getSize();
        if(newVA < extent) {
            newVA = extent;
        }
        git++;
    }

    // skip a few
    newVA += 4;

    // create a new data section from the table
    DataSection *ds = tableToDataSection(newVA, table);
    
    // add to global data section list
    globaldata.push_back(*ds);

    // create the GlobalVariable
    string bufferName = "data_0x" + to_string<VA>(newVA, hex);
    StructType *st_opaque = StructType::create(M->getContext());
    GlobalVariable *gv = new GlobalVariable(*M,
                            st_opaque, 
                            true,
                            GlobalVariable::InternalLinkage,
                            NULL,
                            bufferName);

    vector<Type*> data_section_types;
    vector<Constant*>    secContents;

    dataSectionToTypesContents(globaldata, 
            *ds, 
            M, 
            secContents, 
            data_section_types, 
            false);

    st_opaque->setBody(data_section_types, true);
    Constant *cst = ConstantStruct::get(st_opaque, secContents);
    gv->setAlignment(4);
    gv->setInitializer(cst);

    return true;

} 
bool addJumpTableDataSection(NativeModulePtr natMod,
        Module *M,
        VA &newVA,
        const MCSJumpTable& table)
{
    return addTableDataSection<MCSJumpTable>(natMod, M, newVA, table);
}

bool addJumpIndexTableDataSection(NativeModulePtr natMod,
        Module *M,
        VA &newVA,
        const JumpIndexTable& table)
{
    return addTableDataSection<JumpIndexTable>(natMod, M, newVA, table);
}

void doJumpTableViaData(
        BasicBlock *& block, 
        Value *fptr,
        const int bitness)
{
    Function *ourF = block->getParent();
    //make the call, the only argument should be our parents arguments
    TASSERT(ourF->arg_size() == 1, "");


    if(!fptr->getType()->isPtrOrPtrVectorTy()) {
        Module *M = ourF->getParent();
        // get mem address
        std::vector<Type *>  args;
        args.push_back(g_PRegStruct);
        Type  *returnTy = Type::getVoidTy(M->getContext());
        FunctionType *FT = FunctionType::get(returnTy, args, false);

        PointerType *FptrTy = PointerType::get(FT, 0);
        fptr = new IntToPtrInst(fptr, FptrTy, "", block);
    }

    //we need to wrap up our current context
    writeLocalsToContext(block, bitness, ABICallStore);

    std::vector<Value*>	subArgs;
    subArgs.push_back(ourF->arg_begin());
    CallInst *c = CallInst::Create(fptr, subArgs, "", block);

    //spill our context back
    writeContextToLocals(block, bitness, ABIRetSpill);
}

void doJumpTableViaData(
        NativeModulePtr natM, 
        BasicBlock *& block, 
        InstPtr ip, 
        MCInst &inst,
        const int bitness)
{
    Value *addr = MEM_REFERENCE(0); 
    //doJumpTableViaData(block, addr, bitness);

    llvm::errs() << __FUNCTION__ << ": Doing jump table via data\n";
    Function *ourF = block->getParent();
    Module *M = ourF->getParent();
    // get mem address
    std::vector<Type *>  args;
    args.push_back(g_PRegStruct);
    Type  *returnTy = Type::getVoidTy(M->getContext());
    FunctionType *FT = FunctionType::get(returnTy, args, false);
    
    PointerType *FptrTy = PointerType::get(FT, 0);
    PointerType *Fptr2Ty = PointerType::get(FptrTy, 0);

    Value *func_addr = CastInst::CreatePointerCast(addr, Fptr2Ty, "", block);

    // read in entry from table
    Instruction *new_func = noAliasMCSemaScope(new LoadInst(func_addr, "", block));

    doJumpTableViaData(block, new_func, bitness);
}

template <int bitness>
static void doJumpTableViaSwitch(
        NativeModulePtr natM, 
        BasicBlock *& block, 
        InstPtr ip, 
        MCInst &inst)
{

    llvm::errs() << __FUNCTION__ << ": Doing jumpt table via switch\n";
    Function *F = block->getParent();
    Module *M = F->getParent();
    // we know this conforms to
    // jmp [reg*4+displacement]

    // sanity check
    const MCOperand& scale = OP(1);
    const MCOperand& index = OP(2);

    TASSERT(index.isReg(), "Conformant jump tables need index to be a register");
    TASSERT(scale.isImm() && scale.getImm() == (bitness/8), "Conformant jump tables have scale == 4");

    MCSJumpTablePtr jmpptr = ip->get_jump_table();

    // to ensure no negative entries
    Value *adjustment = CONST_V<bitness>(block, jmpptr->getInitialEntry());
    Value *reg_val = R_READ<bitness>(block, index.getReg());
    Value *real_index = 
        BinaryOperator::Create(Instruction::Add, adjustment, reg_val, "", block);
   
    // create a default block that just traps
    BasicBlock *defaultBlock = 
        BasicBlock::Create(block->getContext(), "", block->getParent(), 0);
    Function *trapFn = Intrinsic::getDeclaration(M, Intrinsic::trap);
    CallInst::Create(trapFn, "", defaultBlock);
    ReturnInst::Create(defaultBlock->getContext(), defaultBlock);
    // end default block

    const std::vector<VA> &jmpblocks = jmpptr->getJumpTable();

    // create a switch inst
    SwitchInst *theSwitch = SwitchInst::Create(
            real_index, 
            defaultBlock,
            jmpblocks.size(),
            block);

    // populate switch
    int myindex = 0;
    for(std::vector<VA>::const_iterator itr = jmpblocks.begin();
        itr != jmpblocks.end();
        itr++) 
    {
        std::string  bbname = "block_0x"+to_string<VA>(*itr, std::hex);
        BasicBlock *toBlock = bbFromStrName(bbname, F);
        TASSERT(toBlock != NULL, "Could not find block: "+bbname);
        theSwitch->addCase(CONST_V<bitness>(block, myindex), toBlock);
        ++myindex;
    }

}

void doJumpTableViaSwitch(
        NativeModulePtr natM, 
        BasicBlock *& block, 
        InstPtr ip, 
        MCInst &inst,
        const int bitness)
{
    switch(bitness)
    {
        case 32:
            return doJumpTableViaSwitch<32>(natM, block, ip, inst);
        case 64:
            return doJumpTableViaSwitch<64>(natM, block, ip, inst);
        default:
            TASSERT(false, "Invalid bitness!");
    }

}


template <int bitness>
static void doJumpTableViaSwitchReg(
        BasicBlock *& block, 
        InstPtr ip, 
        Value *regVal,
        BasicBlock *&default_block)
{

    llvm::errs() << __FUNCTION__ << ": Doing jumpt table via switch(reg)\n";
    Function *F = block->getParent();
    Module *M = F->getParent();
    

    MCSJumpTablePtr jmpptr = ip->get_jump_table();

    // create a default block that just traps
    default_block = 
        BasicBlock::Create(block->getContext(), "", block->getParent(), 0);
    // end default block

    const std::vector<VA> &jmpblocks = jmpptr->getJumpTable();
    std::unordered_set<VA> uniq_blocks(jmpblocks.begin(), jmpblocks.end());

    // create a switch inst
    SwitchInst *theSwitch = SwitchInst::Create(
            regVal, 
            default_block,
            uniq_blocks.size(),
            block);

    // populate switch
    for(auto blockVA : uniq_blocks) 
    {
        std::string  bbname = "block_0x"+to_string<VA>(blockVA, std::hex);
        BasicBlock *toBlock = bbFromStrName(bbname, F);
        llvm::errs() << __FUNCTION__ << ": Mapping from " << to_string<VA>(blockVA, std::hex) << " => " << bbname << "\n";
        TASSERT(toBlock != NULL, "Could not find block: "+bbname);

        ConstantInt *thecase = CONST_V<bitness>(block, blockVA);

        theSwitch->addCase(
                thecase,
                toBlock);
    }

}

void doJumpTableViaSwitchReg(
        BasicBlock *& block, 
        InstPtr ip, 
        Value *regVal,
        BasicBlock *&default_block,
        const int bitness)
{
    switch(bitness)
    {
        case 32:
            return doJumpTableViaSwitchReg<32>(block, ip, regVal, default_block);
        case 64:
            return doJumpTableViaSwitchReg<64>(block, ip, regVal, default_block);
        default:
            TASSERT(false, "Invalid bitness!");
    }
}

static BasicBlock *emitJumpIndexWrite(
        Function *F,
        uint8_t idx_val,
        unsigned dest_reg,
        BasicBlock *contBlock
        ) 
{
    // create new block
    BasicBlock *writeBlock = 
        BasicBlock::Create(F->getContext(), "", F, 0);
    
    // write index to destination register
    R_WRITE<32>(writeBlock, dest_reg, CONST_V<32>(writeBlock, idx_val));

    // jump to continue block
    BranchInst::Create(contBlock, writeBlock);

    return writeBlock; 
}

void doJumpIndexTableViaSwitch(
        BasicBlock *&block, 
        InstPtr ip)
{
    Function *F = block->getParent();
    Module *M = F->getParent();
    // we know this conforms to
    // movzx reg32, [base+disp]

    // sanity check
    const MCInst &inst = ip->get_inst();
    const MCOperand& dest = OP(0);
    const MCOperand& base = OP(1);

    TASSERT(base.isReg(), "Conformant jump index tables need base to be a register");
    TASSERT(dest.isReg(), "Conformant jump index tables need to write to a register");

    JumpIndexTablePtr idxptr = ip->get_jump_index_table();

    // to ensure no negative entries
    Value *adjustment = CONST_V<32>(block, idxptr->getInitialEntry());
    Value *reg_val = R_READ<32>(block, base.getReg());
    Value *real_index = 
        BinaryOperator::Create(Instruction::Add, adjustment, reg_val, "", block);
   
    BasicBlock *continueBlock = 
        BasicBlock::Create(block->getContext(), "", F, 0);

    // create a default block that just traps
    BasicBlock *defaultBlock = 
        BasicBlock::Create(block->getContext(), "", F, 0);
    Function *trapFn = Intrinsic::getDeclaration(M, Intrinsic::trap);
    CallInst::Create(trapFn, "", defaultBlock);
    BranchInst::Create(continueBlock, defaultBlock);
    // end default block

    const std::vector<uint8_t> &idxblocks = idxptr->getJumpIndexTable();


    // create a switch inst
    SwitchInst *theSwitch = SwitchInst::Create(
            real_index, 
            defaultBlock,
            idxblocks.size(),
            block);

    // populate switch
    int myindex = 0;
    for(std::vector<uint8_t>::const_iterator itr = idxblocks.begin();
        itr != idxblocks.end();
        itr++) 
    {
        BasicBlock *writeBl = emitJumpIndexWrite(F, *itr, dest.getReg(), continueBlock );
        theSwitch->addCase(CONST_V<32>(block, myindex), writeBl);
        ++myindex;
    }

    // new block to write to is continue block
    block = continueBlock;
}
