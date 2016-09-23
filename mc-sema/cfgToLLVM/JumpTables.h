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
#ifndef _JUMPTABLES_H
#define _JUMPTABLES_H
#include <boost/shared_ptr.hpp>
#include <boost/cstdint.hpp>
#include <string>
#include <vector>
#include <utility>

template <class T> class Table {
public:
    Table(const std::vector<T> &table, int entry): m_table(table), m_entry(entry) {};
    virtual int getInitialEntry() const { return this->m_entry; }
    virtual ~Table() {};
    virtual const std::vector<T>& getTable(void) const { return this->m_table; }
    virtual const std::vector<T>& getConstTable(void) const { return this->m_table; }

protected:
    std::vector<T> m_table;
    int m_entry;
    virtual std::vector<T>& getTable(void) { return this->m_table; }
};

class MCSOffsetTable : public Table< std::pair<VA,VA> > {
    protected:
        VA m_start_addr;
    public:
        MCSOffsetTable(const std::vector< std::pair<VA,VA> > &table, int entry, VA start): 
            Table< std::pair <VA,VA>>::Table(table, entry), m_start_addr(start) {};
        virtual ~MCSOffsetTable() {};

        virtual VA getStartAddr() const {return this->m_start_addr;}
};

class MCSJumpTable : public Table<VA> {

protected:
    VA m_offset_from_data;
public:
    MCSJumpTable(const std::vector<VA> &table, int entry, VA data_offset): 
        Table<VA>::Table(table, entry), m_offset_from_data(data_offset) {};
    virtual const std::vector<VA>& getJumpTable(void) const { return this->getTable(); }
    virtual std::vector<VA>& getJumpTable(void) { return this->getTable(); }
    virtual VA getOffsetFromData() const {return this->m_offset_from_data; }
    virtual ~MCSJumpTable() {};

};

class JumpIndexTable : public Table<uint8_t> {
public:
    JumpIndexTable(const std::vector<uint8_t> &table, int entry): 
        Table<uint8_t>::Table(table, entry) {};
    virtual const std::vector<uint8_t>& getJumpIndexTable(void) const { return this->getTable(); }
    virtual std::vector<uint8_t>& getJumpIndexTable(void) { return this->getTable(); }
    virtual ~JumpIndexTable() {};

};


typedef boost::shared_ptr<MCSJumpTable> MCSJumpTablePtr;
typedef boost::shared_ptr<JumpIndexTable> JumpIndexTablePtr;


bool addJumpTableDataSection(NativeModulePtr natMod, 
        llvm::Module *M, 
        VA  &newVA, 
        const MCSJumpTable& table);

bool addJumpIndexTableDataSection(NativeModulePtr natMod, 
        llvm::Module *M, 
        VA &newVA, 
        const JumpIndexTable& table);

// check for the format:
// jmp [reg*4+<relocated offset>]
static bool isConformantJumpInst(InstPtr jmpinst) {

    const llvm::MCInst &inst = jmpinst->get_inst();

    // these are now done via switch()
    if(inst.getOpcode() == llvm::X86::JMP32r ||
	   inst.getOpcode() == llvm::X86::JMP64r) {
        return true;
    }

    if (inst.getNumOperands() < 4) {

        return false;
    }
    const llvm::MCOperand& scale = inst.getOperand(1);
    const llvm::MCOperand& index = inst.getOperand(2);
    const llvm::MCOperand& disp = inst.getOperand(3);

    if(scale.isImm() &&             // scale:
                                   // can be 4 (32-bit) or 8 (64-bit)
       (scale.getImm() == 4 || scale.getImm() == 8) &&
       index.isReg() &&             // index must be a register
       disp.isImm()) 
    {        
        return true;
    }

    return false;
}

void doJumpTableViaData(
        NativeModulePtr natM, 
        llvm::BasicBlock *& block, 
        InstPtr ip, 
        llvm::MCInst &inst,
        const int bitness);

void doJumpTableViaData(
        llvm::BasicBlock *& block, 
        llvm::Value *val,
        const int bitness);

void doJumpTableViaSwitch(
        NativeModulePtr natM, 
        llvm::BasicBlock *& block, 
        InstPtr ip, 
        llvm::MCInst &inst,
        const int bitness);

void doJumpTableViaSwitchReg(
        llvm::BasicBlock *& block, 
        InstPtr ip, 
        llvm::Value *regVal,
        llvm::BasicBlock *&default_block,
        const int bitness);

void doJumpIndexTableViaSwitch(
        llvm::BasicBlock *& block, 
        InstPtr ip);

void doJumpOffsetTableViaSwitchReg(
        llvm::BasicBlock *& block, 
        InstPtr ip, 
        llvm::Value *regVal,
        llvm::BasicBlock *&default_block,
        llvm::Value *data_location,
        MCSOffsetTablePtr ot_ptr);

#endif
