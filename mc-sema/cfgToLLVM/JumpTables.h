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

template <class T> class Table {
public:
    Table(const std::vector<T> &table, int entry): m_table(table), m_entry(entry) {};
    virtual int getInitialEntry() const { return this->m_entry; }
    virtual ~Table() {};

protected:
    std::vector<T> m_table;
    int m_entry;
    virtual const std::vector<T>& getTable(void) const { return this->m_table; }
    virtual std::vector<T>& getTable(void) { return this->m_table; }
};

class JumpTable : public Table<VA> {

public:
    JumpTable(const std::vector<VA> &table, int entry): 
        Table<VA>::Table(table, entry) {};
    virtual const std::vector<VA>& getJumpTable(void) const { return this->getTable(); }
    virtual std::vector<VA>& getJumpTable(void) { return this->getTable(); }
    virtual ~JumpTable() {};

};

class JumpIndexTable : public Table<uint8_t> {
public:
    JumpIndexTable(const std::vector<uint8_t> &table, int entry): 
        Table<uint8_t>::Table(table, entry) {};
    virtual const std::vector<uint8_t>& getJumpIndexTable(void) const { return this->getTable(); }
    virtual std::vector<uint8_t>& getJumpIndexTable(void) { return this->getTable(); }
    virtual ~JumpIndexTable() {};

};


typedef boost::shared_ptr<JumpTable> JumpTablePtr;
typedef boost::shared_ptr<JumpIndexTable> JumpIndexTablePtr;


bool addJumpTableDataSection(NativeModulePtr natMod, 
        llvm::Module *M, 
        VA  &newVA, 
        const JumpTable& table);

bool addJumpIndexTableDataSection(NativeModulePtr natMod, 
        llvm::Module *M, 
        VA &newVA, 
        const JumpIndexTable& table);

// check for the format:
// jmp [reg*4+<relocated offset>]
static bool isConformantJumpInst(InstPtr jmpinst) {

    const llvm::MCInst &inst = jmpinst->get_inst();

    const llvm::MCOperand& scale = inst.getOperand(1);
    const llvm::MCOperand& index = inst.getOperand(2);
    const llvm::MCOperand& disp = inst.getOperand(3);

    if(scale.isImm() &&             // scale:
       scale.getImm() == 4 &&       // must be an immediate and be 4
       index.isReg() &&             // index must be a register
       disp.isImm() &&              // displacement must be an imm32
       disp.getImm() == 0) {        // and be 0, since its relocated

        return true;
    }

    return false;
}

void doJumpTableViaData(
        NativeModulePtr natM, 
        llvm::BasicBlock *& block, 
        InstPtr ip, 
        llvm::MCInst &inst);

void doJumpTableViaSwitch(
        NativeModulePtr natM, 
        llvm::BasicBlock *& block, 
        InstPtr ip, 
        llvm::MCInst &inst);

void doJumpIndexTableViaSwitch(
        llvm::BasicBlock *& block, 
        InstPtr ip);

#endif
