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
#include <bincomm.h>
#include <peToCFG.h>
#include <LExcn.h>
#include "../common/to_string.h"
#include "ExternalFuncMap.h"
#include "X86.h"
#include "Externals.h"
#include "JumpTables.h"
#include "ELFTarget.h"
#include "llvm/Support/Debug.h"
#include <iostream>
#include <algorithm>

using namespace std;
using namespace boost;
using namespace llvm;

static bool isAddrOfType(
        ExecutableContainer *c,
        VA addr,
        ExecutableContainer::SectionType st)
{

    vector<ExecutableContainer::SectionDesc>  secs;

    if(!c->get_sections(secs)) throw LErr(__LINE__, __FILE__, "Sections");

    for(vector<ExecutableContainer::SectionDesc>::iterator it = secs.begin(),
            e = secs.end();
            it != e;
            ++it)
    {
        if(it->type == st &&
           addr >= it->base &&
           addr < it->base+it->contents.size())
        {
            return true;
        }

    }

    return false;
}

static
void addDataBlob(   DataSection &ds,
                VA base,
                const vector<uint8_t> &bytes,
                VA start,
                VA end)
{
    if (start == end) {
        return;
    }

    vector<uint8_t> subrange(
            bytes.begin() + (start-base),
            bytes.begin() + (end-base));

    DataSectionEntry dse(start, subrange);

    ds.addEntry(dse);
}

static
void addDataSymbol(   DataSection &ds,
                VA base,
                const std::string &symbol,
                VA symbol_size)
{
    DataSectionEntry dse(base, symbol, symbol_size);

    ds.addEntry(dse);
}

DataSection processDataSection( ExecutableContainer *c,
                                const ExecutableContainer::SectionDesc &sec,
                                VA min_limit = 0x0ULL,
                                VA max_limit = 0xFFFFFFFFFFFFFFFFULL)
{

    VA base = sec.base;
    const vector<uint8_t> &bytes = sec.contents;
    VA size = base+bytes.size();
    unsigned blob_count=0;
    DataSection ds;
    VA addr = base;
    VA prev = base;

    // ensure our limits are sane for this section
    if(min_limit < base) {  min_limit = base;}
    if(max_limit > size) {
        max_limit = size;
    }

    dbgs() << "Section: " << sec.secName << "\n";
    dbgs() << "\tMinimum: " << to_string<VA>(min_limit, hex) << "\n";
    dbgs() << "\tMaximum: " << to_string<VA>(max_limit, hex) << "\n";


    LASSERT(min_limit <= max_limit, "Minimum must be greater than maximum");

    for(vector<VA>::const_iterator reloc_itr = sec.reloc_addrs.begin();
            reloc_itr != sec.reloc_addrs.end();
            reloc_itr++)
    {
        // fix address from section relative to absolute
        addr = base+*reloc_itr;

        dbgs() << "\tFound relocation at: " << to_string<VA>(addr, hex) << "\n";

        if(addr < min_limit || addr > max_limit) {
            dbgs() << __FUNCTION__ << ": Address outside limits: " << to_string<VA>(addr ,hex) << "\n";
            continue;
        }

        std::string symname;
        // see if this address points to a symbol
        VA new_addr;
		VA reloc_size = 0;
        if(c->relocate_addr(addr, new_addr, reloc_size) ) {

            if(addr > prev) {
                addDataBlob(ds, base, bytes, prev, addr);
            }

            prev = addr;


            if(isAddrOfType(c, new_addr, ExecutableContainer::CodeSection))
            {
                string new_sym = "sub_" + to_string<VA>(new_addr, hex);
                llvm::outs() << __FUNCTION__ << ": Recovered function symbol from data section: " << new_sym << "\n";
                addDataSymbol(ds, addr, new_sym, reloc_size);
            } else if ( isAddrOfType(c, new_addr, ExecutableContainer::DataSection)) {
                string new_sym = "dta_" + to_string<VA>(new_addr, hex);
                llvm::outs() << __FUNCTION__ << ": Recovered data symbol from data section: " << new_sym << "\n";
                addDataSymbol(ds, addr, new_sym, reloc_size);
            } else {
                assert(!"address in unsupported section type!");
            }

            prev += reloc_size;

        } else {
            llvm::dbgs() << __FUNCTION__<< ": WARNING: relocation at address (0x" << to_string<VA>(addr, hex) << ") but no symbol found!\n";
        }

    }

    addDataBlob(ds, base, bytes, prev, size);

    return ds;
}

bool getSectionForAddr(
        ExecutableContainer *c,
        VA addr,
        ExecutableContainer::SectionDesc &sd)
{
    vector<ExecutableContainer::SectionDesc>  secs;

    if(!c->get_sections(secs)) throw LErr(__LINE__, __FILE__, "Sections");

    for(vector<ExecutableContainer::SectionDesc>::iterator it = secs.begin(),
            e = secs.end();
            it != e;
            ++it)
    {
        ExecutableContainer::SectionDesc  s = *it;

        VA base = s.base;
        if(addr >= base && addr < base+s.contents.size()) {
            sd = s;
            return true;
        }

    }

    return false;
}

static void addDataEntryPointsFromSection(
        ExecutableContainer *c,
        ExecutableContainer::SectionDesc  &s,
        list<VA>      &entryPoints,
        VA lower_limit,
        VA upper_limit,
        raw_ostream         &out)
{
    VA addr;

    out << __FUNCTION__ << "Bounds are: " << to_string<VA>(lower_limit, hex)
                        << " to " << to_string<VA>(upper_limit, hex) << "\n";

    for(vector<VA>::const_iterator reloc_itr = s.reloc_addrs.begin();
            reloc_itr != s.reloc_addrs.end();
            reloc_itr++)
    {
        addr = s.base+*reloc_itr;

        // skip addresses not in limits
        if(addr < lower_limit || addr > upper_limit) {
            out << __FUNCTION__ << "Relocation address out of bounds: " << to_string<VA>(addr, hex) << "\n";
            continue;
        }

        VA  new_addr;
		VA 	symbol_size;
        out << __FUNCTION__ << ": Looking at relocation at: " << to_string<VA>(addr, hex) << "\n";
        if(c->relocate_addr(addr, new_addr, symbol_size )) {
            if( isAddrOfType(c, new_addr, ExecutableContainer::CodeSection))
            {
                out << __FUNCTION__ << ": Adding data entry point for: sub_"
                    << to_string<VA>(new_addr, hex) << "\n";
                if(find( entryPoints.begin(), entryPoints.end(), new_addr)
                        == entryPoints.end())
                {
                    entryPoints.push_back(new_addr);
                }
            } else {
                out << __FUNCTION__ << ": Relocation does not point to code: "
                    << to_string<VA>(new_addr, hex) << "\n";
            }
        } else {
                out << __FUNCTION__ << ": Could not process reloc at: "
                    << to_string<VA>(addr, hex) << "\n";
         }
    }

}


static
ExternalDataRefPtr makeExtDataRefFromString(const string &dataName, ExternalFunctionMap &f) {
  ExternalDataRefPtr p;
  int dataSize;
  bool res;

  res = f.get_data_size(dataName, dataSize);
  LASSERT(res, "Could not get data size for:"+dataName);

  ExternalDataRef  *t = new ExternalDataRef(dataName, dataSize);

  return ExternalDataRefPtr(t);
}


static
ExternalCodeRefPtr makeExtCodeRefFromString(string callName, ExternalFunctionMap &f) {
  ExternalCodeRefPtr                           p;
  bool                                    res;
  ExternalFunctionMap::CallingConvention  conv;
  bool                                    isNoReturn;
  int                                     numParams;

  //lookup call name in function map
  string  s = f.sym_sym(callName);
  LASSERT(s.size() != 0, "Failure with sym_sym for symbol "+callName);

  res = f.get_calling_convention(s, conv);
  LASSERT(res, "Could not find calling convention for "+s);
  res = f.get_noreturn(s, isNoReturn);
  LASSERT(res, "Could not find no return for "+s);
  res = f.get_num_stack_params(s, numParams);
  LASSERT(res, "Could not find number of stack params for "+s);
  LASSERT(numParams >= 0, "Invalid number of arguments for extcall:"+s+". Is it in your external call map file?");

  //make an ExternalCodeRef
  ExternalCodeRef::ReturnType        rty = ExternalCodeRef::Unknown;
  ExternalCodeRef::CallingConvention c;

  switch(conv) {
  case ExternalFunctionMap::CalleeCleanup:
    c = ExternalCodeRef::CalleeCleanup;
    break;
  case ExternalFunctionMap::CallerCleanup:
    c = ExternalCodeRef::CallerCleanup;
    break;
  case ExternalFunctionMap::FastCall:
    c = ExternalCodeRef::FastCall;
    break;
  case ExternalFunctionMap::X86_64_SysV:
    c = ExternalCodeRef::X86_64_SysV;
    break;
  case ExternalFunctionMap::X86_64_Win64:
  	c = ExternalCodeRef::X86_64_Win64;
  default:
    assert(!"Invalid calling convention for external call!");

  }

  if(isNoReturn) {
    rty = ExternalCodeRef::NoReturn;
  }

  std::string funcSign;
  bool sign = f.get_function_sign(s, funcSign);

  ExternalCodeRef  *t = NULL;

  if(sign){
  	t = new ExternalCodeRef(s, numParams, c, rty, funcSign);
  } else {
 	t = new ExternalCodeRef(s, numParams, c, rty);
  }
  return ExternalCodeRefPtr(t);
}

// this function determines if an instruction can reference
// a pointer to code
//
// **while JMP and CALL can do this, they have separate handlers**
//
// and are not included in here
// this is used to identify function references for callbacks
// as an example:
//
// push offset function_name
// call do_a_callback
//
// the goal is to add function_name to the "disassemble at these entrypoints"
// list

static bool canInstructionReferenceCode( InstPtr inst) {
    switch(inst->get_inst().getOpcode()) {
        case X86::MOV32mi:      // writes to memory, but uses an immediate, which could be code
        case X86::MOV32o32a:    // writes imm32 to eax; probably code
        case X86::MOV32ri:      // writes imm32 to register, could be code
        case X86::PUSHi32:      // push an imm32, which could be code

        case X86::MOV64mi32:
        case X86::MOV64mr:
        case X86::MOV32mr:
	case X86::MOV64rm:
	case X86::LEA64r:

        // need to check if mem references are valid here
        case X86::MOV32rm:      // writes mem to register, mem could be code?
        case X86::PUSH32rmm:    // push mem, which could be/have code
        //case X86::LEA32r:       // write address of mem to reg
            return true;

        default:
            return false;

    }
}

// return true if this instruction
// branches via a memory lookup
static bool isBranchViaMemory(InstPtr inst) {

    switch(inst->get_inst().getOpcode()) {
        case X86::JMP32m:
        case X86::JMP64m:
        case X86::CALL32m:
        case X86::CALL64m:
            return true;
        default:
            return false;
    }
}

static int addJmpTableEntries(ExecutableContainer *c,
        vector<VA> &new_funcs,
        VA curAddr,
        int increment,
        raw_ostream &out) {

    int num_funcs_added = 0;

    while(true) {

        VA  someFunction;
		VA  size;
        curAddr += increment;

        if(!c->relocate_addr(curAddr, someFunction, size)) {
            // could not relocate the default jump table entry.
            // not good
            out << "Jump table search ending, can't relocate address: " << to_string<VA>(curAddr, hex) << "\n";
            break;
        }

        bool is_reloc_code = isAddrOfType(c, someFunction,
                ExecutableContainer::CodeSection);

        if(!is_reloc_code) {
            // jump table entry not point to code
            out << "Jump table search ending, addr " << to_string<VA>(curAddr, hex) << " doesn't point to code\n";
            break;
        }

        num_funcs_added += 1;
        out << "Added JMPTABLE entry [" << to_string<VA>(curAddr, hex)
            << "] => " << to_string<VA>(someFunction, hex)  << "\n";
        new_funcs.push_back(someFunction);

    }

    return num_funcs_added;
}

// returns the first register this instruction uses
// meant to be run on jmp [reg*imm+imm32]
static int regFromInst(const MCInst &inst) {
    for(int i = 0; i < inst.getNumOperands(); i++) {
        const MCOperand &op = inst.getOperand(i);
        if(op.isReg()) {
            return op.getReg();
        }
    }

    return -1;
}

// this should check if the given instruction writes
// to register 'reg'. Right now it just checks if the
// instruction uses the register 'reg'.
static int writesToReg(const MCInst &inst, unsigned reg)
{
    for(int i = 0; i < inst.getNumOperands(); i++) {
        const MCOperand &op = inst.getOperand(i);
        if(op.isReg() && op.getReg() == reg) {
            return true;
        }
    }

    return false;
}

static bool parseJumpIndexTable(ExecutableContainer *c,
        InstPtr index_insn,
        const vector<VA> &jmptable_entries,
        raw_ostream &out)
{
    VA reloc_offset = index_insn->get_reloc_offset(Inst::MEMRef);
    if (reloc_offset == 0)  {
        out << "Unsupported jump index write; no relocation\n";
        // this jump index probably doesn't use a table
        return false;
    }

    VA  addrInInst = index_insn->get_loc() + reloc_offset;
    VA  indexTableEntry;
	VA  symbolSize;
    if(!c->relocate_addr(addrInInst, indexTableEntry, symbolSize)) {
        out << "Not a jump index table: can't relocate relocation in index insn\n";
        // can't relocate, something bad happened
        return false;
    }

    // assume we always index the start of the index table
    // ... might not be correct

    // this means we set initial entry to zero, the first element
    int initial_entry = 0;

    uint8_t b;
    int bindex = 0;
    // loop while all the bytes we read can be table indexes
    vector<uint8_t> index_entries;

    while( (indexTableEntry+bindex) < c->getExtent() ) {
        c->readByte(indexTableEntry+bindex, &b);
        if (b > jmptable_entries.size())
        {
            break;
        }
        out << "Read index table byte: " << to_string<uint32_t>((uint32_t)b, hex) << "\n";
        index_entries.push_back(b);
        bindex++;
    }

    JumpIndexTable *jit = new JumpIndexTable(index_entries, initial_entry);

    index_insn->set_jump_index_table(JumpIndexTablePtr(jit));


    return true;
}

static bool processJumpIndexTable(ExecutableContainer *c,
        NativeBlockPtr B,
        InstPtr jmpinst,
        const vector<VA> &jmptable_entries,
        raw_ostream &out)
{
    // first, find which operand was the index
    // register in jmpinst
    //
    const MCInst &inst = jmpinst->get_inst();
    int index_reg = regFromInst(inst);
    if(index_reg == -1) {
        out << "JMPINST does not use a register to index\n";
        return false;
    }

    // loop backwards through block looking for
    // instructions that write to this register
    const std::list<InstPtr> &block_insts = B->get_insts();
    InstPtr write_reg_insn;
    for( std::list<InstPtr>::const_reverse_iterator itr = block_insts.rbegin();
        itr != block_insts.rend();
        itr++)
    {
        // check if we 'write to a register'
        if(writesToReg((*itr)->get_inst(), index_reg)) {
            write_reg_insn = *itr;
            break;
        }
    }

    if(write_reg_insn == NULL) {
        out << "No instruction writes index register in the same basic block\n";
        return false;
    }

    out << "Found register index write instruction:\n";

    if(!parseJumpIndexTable(c, write_reg_insn,
            jmptable_entries, out)) {
        out << "Could not parse jump index table, aborting\n";
        return false;
    }

    return true;

}

static bool handlePossibleJumpTable(ExecutableContainer *c,
        NativeBlockPtr B,
        InstPtr jmpinst,
        VA curAddr,
        stack<VA> &funcs,
        stack<VA> &blockChildren,
        raw_ostream &out) {

    LASSERT(jmpinst->get_inst().getOpcode() == X86::JMP32m ||
            jmpinst->get_inst().getOpcode() == X86::JMP64m,
            "handlePossibleJumpTable needs a JMP32m/JMP64m opcode"  );

    // is this a jump table, step 0
    // does this instruction have a relocation?
    VA reloc_offset = jmpinst->get_reloc_offset(Inst::MEMRef);
    if (reloc_offset == 0)  {
        out << "Not a jump table: no relocation in JMP32m\n";
        // bail, this is not a jump table
        return false;
    }

    // this relocation has to point to a relocation

    VA addrInInst = curAddr + reloc_offset;
    VA jmpTableEntry, someFunction;
	VA symbolSize;
    if(!c->relocate_addr(addrInInst, jmpTableEntry, symbolSize)) {
        out << "Not a jump table: can't relocate relocation in JMP32m\n";
        // can't relocate, something bad happened
       return false;
    }

    if(!c->relocate_addr(jmpTableEntry, someFunction, symbolSize)) {
        // could not relocate the default jump table entry.
        // not good
        out << "Not a jump table: can't relocate first jump table entry\n";
        return false;
    }

    bool is_reloc_code = isAddrOfType(c, someFunction, ExecutableContainer::CodeSection);
    if(!is_reloc_code) {
        // jump table entry not point to code
        out << "Not a jump table: first entry doesn't point to code\n";
        return false;
    }


    // read jump table entries and add them as new function
    // entry points
    vector<VA> jmptable_entries;
    int new_funs;
    int original_zero;

    // this reads negative jump table indexes, but vectors are not negative
    // indexed. the negative most, which should be the new index 0, is now
    // index N. Reverse the vector so it will be index 0, and save the current
    // size as the original zeroth element
    new_funs = addJmpTableEntries(c, jmptable_entries, jmpTableEntry,  -4, out);
    std::reverse(jmptable_entries.begin(), jmptable_entries.end());
    out << "Added: " << to_string<int>(new_funs, dec) << " functions to jmptable\n";

    original_zero = new_funs;

    // add original entry at the zero position
    jmptable_entries.push_back(someFunction);
    out << "Added JMPTABLE entry [" << to_string<uint32_t>(jmpTableEntry, hex)
        << "] => " << to_string<uint32_t>(someFunction, hex)  << "\n";

    // add the positive table entries
    new_funs = addJmpTableEntries(c, jmptable_entries, jmpTableEntry,  4, out);
    out << "Added: " << to_string<int>(new_funs, dec) << " functions to jmptable\n";

    // associate instruction with jump table
    MCSJumpTable *jt = new MCSJumpTable(jmptable_entries, original_zero, (VA)(-1));
    jmpinst->set_jump_table(MCSJumpTablePtr(jt));

    stack<VA> *toPush = NULL;

    // if this jump table is in the format
    // jmp [reg*4+imm32], then it is conformant
    // and we can turn it into an llvm switch();
    bool is_conformant = isConformantJumpInst(jmpinst);
    if(is_conformant) {
        toPush = &blockChildren;
        out << "GOT A CONFORMANT JUMP INST\n";
    } else {
        toPush = &funcs;
    }

    // add these jump table entries as new entry points
    for(std::vector<VA>::const_iterator itr = jmptable_entries.begin();
            itr != jmptable_entries.end();
            itr++)
    {
        out << "Adding block via jmptable: " << to_string<VA>(*itr, hex) << "\n";
        toPush->push(*itr);
        if(is_conformant) {
            B->add_follow(*itr);
        }
    }

    processJumpIndexTable(c, B, jmpinst, jmptable_entries, out);

    return true;

}


static bool handleJump(ExecutableContainer *c,
        NativeBlockPtr B,
        InstPtr jmpinst,
        VA curAddr,
        stack<VA> &funcs,
        stack<VA> &blockChildren,
        raw_ostream &out) {

  // this is an internal jmp. probably a jump table.
  out << "Found a possible jump table!\n";
  bool did_jmptable = handlePossibleJumpTable(c, B, jmpinst, curAddr, funcs, blockChildren, out);

  if(!did_jmptable) {
    out << "Heristic jumptable processing couldn't parse jumptable\n";
    out << "pointing to: 0x" << to_string<VA>(curAddr, hex) << "\n";
    out << jmpinst->printInst() << "\n";
    out << c->hash << "\n";
  }
  return did_jmptable;

}

/*
 *
static void addDataEntryPointsFromSection(
        ExecutableContainer *c,
        ExecutableContainer::SectionDesc  &s,
        list<uint64_t>      &entryPoints,
        VA lower_limit,
        VA upper_limit,
        raw_ostream         &out)
        */
bool treatCodeAsData( ExecutableContainer *c,
        uint32_t            addr,
        uint32_t            size,
        list<VA>           &funcs) {

    ExecutableContainer::SectionDesc sd;
    if(!getSectionForAddr(c, addr, sd)) {
        return false;
    }

    if (size != 0) {
        addDataEntryPointsFromSection(c, sd, funcs, addr, addr+size, llvm::outs() );
        processDataSection(c, sd, addr, addr+size);
    }

    return true;
}

bool dataInCodeHeuristic(
        ExecutableContainer *c,
        InstPtr             I,
        uint32_t            addr,
        list<VA>           &funcs,
		uint32_t 			relocSize)
{
    // detect SEH handler
   if(I->get_inst().getOpcode() == X86::PUSHi32) {
       uint32_t dw1;
       uint8_t *ptr = (uint8_t*)&dw1;
       c->readByte(addr+0, ptr+0);
       c->readByte(addr+1, ptr+1);
       c->readByte(addr+2, ptr+2);
       c->readByte(addr+3, ptr+3);
       if(dw1 == 0xFFFFFFFE) {
           llvm::outs() << "WARNING: Heuristically detected SEH handler at: "
               << to_string<VA>(addr, hex) << "\n";
           return treatCodeAsData(c, addr, 0x28, funcs);
       }
   } else {
	   return treatCodeAsData(c, addr, relocSize, funcs);
   }

   return false;

}

// assume the immediate references code if:
// * we are dealing with a fully linked ELF
// * The immediate is in the range of a valid code or data section
static bool setHeuristicRef(ExecutableContainer *c,
        InstPtr I,
        int opnum,
        stack<VA> &funcs,
        raw_ostream &out,
        const std::string whichInst)
{
    MCOperand op;
    std::string imp_name;
    ElfTarget *elft = dynamic_cast<ElfTarget*>(c);
    op = I->get_inst().getOperand(opnum);
    LASSERT(op.isImm(), "No immediate operand for " + whichInst);
    VA imm = op.getImm();


    if(elft && elft->isLinked()) {
       if (elft->is_in_code(imm)) {
            // this instruction references code
            I->set_reference(Inst::IMMRef, imm);
            I->set_ref_type(Inst::IMMRef, Inst::CFGCodeRef);
            // make sure we disassemble at this new address
            funcs.push(imm);
            out << "Found new function entry from " << whichInst << ": " << to_string<VA>(imm, hex) << "\n";
            return true;
       } else if (elft->is_in_data(imm)) {
            out << "Adding local data ref to: " << to_string<VA>(imm, hex) << "\n";
            I->set_reference(Inst::IMMRef, imm);
            I->set_ref_type(Inst::IMMRef, Inst::CFGDataRef);
       } else if (c->find_import_name(imm, imp_name)) {
           out << "Import name is: " << imp_name << "\n";
       }
    }

    return false;
}

NativeBlockPtr decodeBlock( ExecutableContainer *c,
                            ExternalFunctionMap &f,
                            LLVMByteDecoder     &d,
                            stack<VA>           &blockChildren,
                            VA                  e,
                            stack<VA>           &funcs,
                            raw_ostream         &out)
{
    NativeBlockPtr  B = NativeBlockPtr(new NativeBlock(e, d.getPrinter()));
    VA              curAddr = e;
    bool            has_follow = true;

    out << "Processing block: " << B->get_name() << "\n";
    do
    {
        InstPtr I = d.getInstFromBuff(curAddr, c);

        //I, if a terminator, will have true and false targets
        //filled in. I could be an indirect branch of some kind,
        //we will deal with that here. we will also deal with the
        //instruction if it is a data instruction with relocation

        out << to_string<VA>(I->get_loc(), hex) << ":";
        out << I->printInst() << "\n";

        if(I->get_tr() != 0) {
            B->add_follow(I->get_tr());
            has_follow = false;
            out << "Adding block: " << to_string<VA>(I->get_tr(), hex) << "\n";
            blockChildren.push(I->get_tr());
        }

        if(I->get_fa() != 0) {
            B->add_follow(I->get_fa());
            has_follow = false;
            out << "Adding block: " << to_string<VA>(I->get_fa(), hex) << "\n";
            blockChildren.push(I->get_fa());
        }

        if(I->terminator()) {
            has_follow = false;
        }

        //do we need to add a data reference to this instruction?
        //again, because there is no offset information in the
        //instruction decoder, for now we just ask if every addr
        //in the inst is relocated
        for(uint32_t i = 0; i < I->get_len(); i++) {
            VA addrInInst = curAddr+i;
            if(c->is_addr_relocated(addrInInst)) {
                VA  addr = 0;
				VA  relocSize;
                std::string has_imp;

                out << __FUNCTION__ << ": have reloc at: " << to_string<VA>(addrInInst, hex) << "\n";

                // this instruction has a relocation
                // save the relocation offset for later
                I->set_reloc_offset(Inst::MEMRef, i);

                //get the offset for this address
                //add it as a data offset to the instruction
                if (c->find_import_name(addrInInst, has_imp) )  {

                    if(f.is_data(has_imp))
                    {
                        ExternalDataRefPtr data_p = makeExtDataRefFromString(has_imp, f);
                        out << "Adding external data ref: " << has_imp << "\n";
                        I->set_ext_data_ref(data_p);
                    }
                    else
                    {
                        ExternalCodeRefPtr code_p = makeExtCodeRefFromString(has_imp, f);
                        LASSERT(code_p, "Failed to get ext call from map for symbol: "+has_imp);
                        //maybe, this call doesn't return, in which case,
                        //we should kill the decoding of this flow
                        if(code_p->getReturnType() == ExternalCodeRef::NoReturn) {
                            has_follow = false;
                        }
                        out << "Adding external code ref: " << has_imp << "\n";
                        I->set_ext_call_target(code_p);
                    }

                } else if(c->relocate_addr(addrInInst, addr, relocSize)) {
                    bool can_ref_code = canInstructionReferenceCode(I);
                    bool is_reloc_code = isAddrOfType(c, addr, ExecutableContainer::CodeSection);
                    bool is_reloc_data = isAddrOfType(c, addr, ExecutableContainer::DataSection);
                    unsigned opc = I->get_inst().getOpcode();

                    out << "Found a relocation at: 0x" << to_string<VA>(addrInInst, hex)
                        << ", pointing to: 0x" << to_string<VA>(addr, hex) << "\n";

                    if(isBranchViaMemory(I)) {
                        out << "Detect branch via memory, relocation handled later\n";
                    }
                    // this instruction can reference code and does
                    // reference code
                    // so we assume the code points to a function
                    else if( can_ref_code && is_reloc_code ) {
                        list<VA> new_funcs;
                        if(dataInCodeHeuristic(c, I, addr, new_funcs, relocSize)) {
                            // add new functions to our functions list
                            for(list<VA>::const_iterator nfi = new_funcs.begin();
                                    nfi != new_funcs.end();
                                    nfi++)
                            {
                                out << "Adding: 0x" << to_string<VA>(addr, hex) << " as target because of DataInCode heuristic\n";
                                funcs.push(*nfi);
                            }

                            I->set_reference(Inst::MEMRef, addr);
                            I->set_ref_type(Inst::MEMRef, Inst::CFGDataRef);
                        } else {
                            I->set_reference(Inst::MEMRef, addr);
                            I->set_ref_type(Inst::MEMRef, Inst::CFGCodeRef);
                            out << "Adding: 0x" << to_string<VA>(addr, hex) << " as target\n";
                            funcs.push(addr);
                        }
                    }
                    // this instruction can't reference code and points to .text
                    // or references data. Treat as data element
                    // TODO: extract this from .text and shove into .data?
                    else if(( !can_ref_code && is_reloc_code) || is_reloc_data )
                    {
                        out << "Adding data reference to 0x" << to_string<VA>(addr, hex) << "\n";
                        I->set_reference(Inst::MEMRef, addr);
                        I->set_ref_type(Inst::MEMRef, Inst::CFGDataRef);
                    } else {
                        out << "WARNING: relocation points to neither code nor data:" << to_string<VA>(addr, hex) << "\n";
                    }

                } else {
                    out << "*NOT* Relocating relocatable addr:" << to_string<uint32_t>(addrInInst, hex) << "\n";
                }
                break;
            }
        }

        //is this instruction an external call?
        //in a COFF binary, the pcrel call can refer to an
        //external symbol that has been relocated
        //so, get the string that corresponds, and
        //provide the translation using the function map
        MCOperand op;
        string  imp;
        switch(I->get_inst().getOpcode()) {
            case X86::LEA32r:
                setHeuristicRef(c, I, 4, funcs, out, "LEA32r");
                break;
            case X86::PUSHi32:
                setHeuristicRef(c, I, 0, funcs, out, "PUSHi32");
                break;
            case X86::MOV64ri32:
            case X86::MOV64ri:
                setHeuristicRef(c, I, 1, funcs, out, "MOV64ri32");
                break;

            case X86::JMP32m:
            case X86::JMP64m:
                {
                    string  thunkSym;
                    bool did_jmp = false;
                    //bool r = c->find_import_name(curAddr+2, thunkSym);
                    bool r;
                    if(I->has_rip_relative()){
                        r = c->find_import_name(I->get_rip_relative(), thunkSym);
                    } else {
                        r = c->find_import_name(curAddr+2, thunkSym);
                    }
                    if(r) {
                        // this goes to an external API call
                        out << "Adding external code ref via JMP: " << thunkSym << "\n";
                        ExternalCodeRefPtr p = makeExtCodeRefFromString(thunkSym, f);
                        I->set_ext_call_target(p);
                        has_follow = false;
                    } else {

                        did_jmp = handleJump(c, B, I, curAddr, funcs, blockChildren, out);
                        LASSERT(did_jmp, "Unable to resolve jump.");
                    }
                }
                break;
            case X86::CALLpcrel32:
            case X86::CALL64pcrel32:
                {
                    printf("DEBUG : %s, callpcrel\n", __FUNCTION__), fflush(stdout);
                    //this could be an external call in COFF, or not
                    op = I->get_inst().getOperand(0);
                    LASSERT(op.isImm(), "Nonsense for CALLpcrel32");

                    //check to see if this is an external call...
                    if(I->has_ext_call_target()) {
                        out << "External call to: " << I->get_ext_call_target()->getSymbolName() << "\n";
                        break;
                    }

                    bool is_extcall = false;

                    if(op.getImm() !=0 && ((uint32_t)op.getImm()) != 0xFFFFFFFC) {
                        VA    callTgt = curAddr+op.getImm()+I->get_len();
                        bool  foldFunc = false;
                        //speculate about callTgt
                        InstPtr spec = d.getInstFromBuff(callTgt, c);
                        if(spec->terminator() && (spec->get_inst().getOpcode() == X86::JMP32m
                                || spec->get_inst().getOpcode() == X86::JMP64m)) {
                            string  thunkSym;
                            bool r;

                            if(spec->has_rip_relative()){
                                r = c->find_import_name(spec->get_rip_relative(), thunkSym);
                            } else {
                                r = c->find_import_name(callTgt+2, thunkSym);
                            }

                           // bool r = c->find_import_name(callTgt+2, thunkSym);
                            if(r) {
                                is_extcall = true;

                                ExternalCodeRefPtr p = makeExtCodeRefFromString(thunkSym, f);
                                I->set_ext_call_target(p);
                                foldFunc = true;
                                if(p->getReturnType() == ExternalCodeRef::NoReturn) {
                                    has_follow = false;
                                }
                            }


                        }
                        if(foldFunc == false) {
                            //add this to our list of funcs to search
                            out << "Adding: 0x" << to_string<VA>(callTgt, hex) << " as target because its a call target\n";
                            funcs.push(callTgt);
                        }
                    }

                    if(is_extcall == false) {
                        // may be a local call
                        VA addr=curAddr+1, relo_addr=0, reloc_size = 0;
                        out << "Symbol not found, maybe a local call\n";
                        if(c->relocate_addr(addr, relo_addr, reloc_size)){
                            out << "Found local call to: " << to_string<VA>(relo_addr, hex) << "\n";
                            I->set_reference(Inst::MEMRef, relo_addr);
                            I->set_ref_type(Inst::MEMRef, Inst::CFGCodeRef);
                            out << "Adding: 0x" << to_string<VA>(relo_addr, hex) << " as target because its relo-able and internal\n";
                            funcs.push(relo_addr);
                        } else {
                            out << "Could not relocate addr for local call at: ";
                            out << to_string<VA>(curAddr, hex) << "\n";
                            out << "Assuming address should not be relocated\n";
                            VA  local_call_tgt = curAddr+op.getImm()+I->get_len();
                            out << "Found local call to: " << to_string<VA>(local_call_tgt, hex) << "\n";
                            I->set_reference(Inst::IMMRef, local_call_tgt);
                            I->set_ref_type(Inst::IMMRef, Inst::CFGCodeRef);
                            out << "Adding: 0x" << to_string<VA>(local_call_tgt, hex) << " as target because its a non-relocateable internal call\n";
                            funcs.push(local_call_tgt);
                        }
                    }
                }

                break;

            case X86::CALL32m:
            case X86::CALL64m:
                //this should be a call to an external, or we have no idea
                //so we need to try and look up the symbol that we're calling at this address...
                printf("DEBUG : %s, CALL\n", __FUNCTION__), fflush(stdout);
                if(c->find_import_name(curAddr+2, imp)) {
                    ExternalCodeRefPtr p = makeExtCodeRefFromString(imp, f);
                    LASSERT(p, "Failed to get ext call from map for symbol"+imp);

                    out << "Calling symbol: " << p->getSymbolName() << "\n";
                    if(p->getReturnType() == ExternalCodeRef::NoReturn) {
                        has_follow = false;
                    }
                    I->set_ext_call_target(p);
                } else {
                    out << "Cannot find symbol at address ";
                    out << to_string<VA>(curAddr, hex) << "\n";
                }
                break;
        }

        B->add_inst(I);
        curAddr += I->get_len();
    } while(has_follow);

    //we have built a basic block, it might contain
    //multiple calls, but it only has one terminator
    //which is either a ret or a branch
    return B;
}

NativeFunctionPtr getFunc(ExecutableContainer *c,
                          LLVMByteDecoder     &d,
                          stack<VA>           &funcs,
                          ExternalFunctionMap &f,
                          VA                  e,
                          raw_ostream         &out)
{
  NativeFunctionPtr F = NativeFunctionPtr(new NativeFunction(e));
  stack<VA>         toVisit;
  set<VA>           visited;

  toVisit.push(e);

  out << "getFunc: Starting at 0x" << to_string<VA>(e,hex) << "\n";
  out << "getFunc: toVisit size is: " << toVisit.size() << "\n";

  while(toVisit.size() > 0) {
    VA  curBlockHeader = toVisit.top();
    toVisit.pop();

    if(visited.find(curBlockHeader) != visited.end()) {
      continue;
    } else {
      visited.insert(curBlockHeader);
    }

    // funcs is new functions to visit later
    // toVisit is basic blocks of *this* function to visit now
    NativeBlockPtr  B = decodeBlock(c,
                                    f,
                                    d,
                                    toVisit,
                                    curBlockHeader,
                                    funcs,
                                    out);

    F->add_block(B);
  }

  out << "getFunc: Function recovery complete for ";
  out << " func at " << to_string<VA>(e,hex) << "\n";

  F->compute_graph();
  return F;
}

void addDataEntryPoints( ExecutableContainer  *c,
                         list<VA>             &entryPoints,
                         raw_ostream          &out)
{
    vector<ExecutableContainer::SectionDesc>  secs;

    if(!c->get_sections(secs)) throw LErr(__LINE__, __FILE__, "Sections");

    for(auto s : secs)
    {
        if(s.type != ExecutableContainer::DataSection) {
            out << __FUNCTION__ << ": skipping non-data section: " << s.secName << "\n";
            continue;
        } else {
            out << __FUNCTION__ << ": looking for entry points in: " << s.secName << "\n";
        }

        addDataEntryPointsFromSection(c, s, entryPoints,
                s.base,
                s.base+s.contents.size(),
                out);

    }
}

list<NativeFunctionPtr> getFuncs( ExecutableContainer *c,
                                  LLVMByteDecoder     &dec,
                                  set<VA>             &visited,
                                  VA                  e,
                                  ExternalFunctionMap &funcMap,
                                  raw_ostream         &out)
{
  list<NativeFunctionPtr> funcs;
  stack<VA>               toVisit;

  //start from 'e'
  toVisit.push(e);


  while(toVisit.size() > 0) {
    VA  curFuncEntry = toVisit.top();
    toVisit.pop();

    if(visited.find(curFuncEntry) != visited.end()) {
      continue;
    } else {
      visited.insert(curFuncEntry);
    }

    out << "Calling getFunc on: " << to_string<VA>(curFuncEntry, hex) << "\n";

    NativeFunctionPtr thisFunc = getFunc(c, dec, toVisit, funcMap, curFuncEntry, out);
    funcs.push_back(thisFunc);
  }

  return funcs;
}



