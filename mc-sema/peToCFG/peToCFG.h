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
#ifndef _PETOCFG_H
#define _PETOCFG_H
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/ADT/Triple.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/MemoryObject.h"
#include "llvm/Object/COFF.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/MemoryBuffer.h"

#include <stack>
#include <set>
#include <map>
#include <list>
#include <unordered_map>

#include <stdio.h>
#include <assert.h>
#include <iostream>

#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <boost/program_options/config.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/options_description.hpp>

#include <boost/graph/graph_traits.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/graph/adjacency_matrix.hpp>

typedef boost::adjacency_matrix<boost::directedS> CFG;
typedef uint64_t FuncID;
typedef uint64_t VA;

class Inst;
typedef boost::shared_ptr<Inst> InstPtr;

#include <BaseBMO.h>

#include "inst_decoder_fe.h"
#include "../common/to_string.h"

#include "../cfgToLLVM/Externals.h"

class MCSJumpTable;
class JumpIndexTable;
class MCSOffsetTable;
typedef boost::shared_ptr<ExternalCodeRef> ExternalCodeRefPtr;
typedef boost::shared_ptr<ExternalDataRef> ExternalDataRefPtr;
typedef boost::shared_ptr<MCSJumpTable> MCSJumpTablePtr;
typedef boost::shared_ptr<JumpIndexTable> JumpIndexTablePtr;
typedef boost::shared_ptr<MCSOffsetTable> MCSOffsetTablePtr;

class BufferMemoryObject : public llvm::MemoryObject {
 private:
  std::vector<uint8_t> Bytes;
 public:
  BufferMemoryObject(const uint8_t *bytes, uint64_t length) {
    for (unsigned int i = 0; i < length; i++) {
      this->Bytes.push_back(bytes[i]);
    }
    return;
  }

  uint64_t getBase() const {
    return 0;
  }
  uint64_t getExtent() const {
    return this->Bytes.size();
  }

  int readByte(uint64_t addr, uint8_t *byte) const {
    if (addr > this->getExtent())
      return -1;
    *byte = this->Bytes[addr];
    return 0;
  }
};

/* we're going to make some assumptions about external calls:
 *  - they have some sane calling convention
 *  - they take a defined number of arguments
 *  - they either return no values and have no effects on local
 registers, or, they return a single integer value and
 assign that value to the EAX register
 */

class Inst {
 public:
  enum Prefix {
    NoPrefix,
    RepPrefix,
    RepNePrefix,
    FSPrefix,
    GSPrefix
  };

  enum CFGRefType {
    CFGCodeRef,
    CFGDataRef
  };

  enum CFGOpType {
    IMMRef,
    MEMRef
  };

 private:
  std::vector<VA> targets;
  std::vector<uint8_t> instBytes;
  VA tgtIfTrue;
  VA tgtIfFalse;
  VA loc;
  llvm::MCInst NativeInst;
  std::string instRep;
  ExternalCodeRefPtr extCallTgt;
  ExternalDataRefPtr extDataRef;

  MCSJumpTablePtr jumpTable;
  bool jump_table;
  JumpIndexTablePtr jumpIndexTable;
  bool jump_index_table;

  Prefix pfx;
  bool ext_call_target;
  bool ext_data_ref;
  bool is_call_external;
  uint8_t len;
  bool is_terminator;

  // relocation offset: the number of bytes from the start of the instruction
  // that there is a relocation.
  // Zero if there is no relocation that occurs in the bytes of this
  // instruction
  uint64_t imm_reloc_offset;
  uint64_t imm_reference;
  CFGRefType imm_ref_type;
 public:
  bool has_imm_reference;
 private:

  uint64_t mem_reloc_offset;
  uint64_t mem_reference;
  CFGRefType mem_ref_type;
 public:
  bool has_mem_reference;
 private:

  uint32_t arch;
  //  if this instruction is a system call, its system call number
  //  otherwise, -1
  int system_call_number;
  bool local_noreturn;

  VA rip_target;
  bool hasRIP;
 public:
  VA offset_table;
  std::vector<uint8_t> get_bytes(void) {
    return this->instBytes;
  }
  std::string printInst(void) {
    return this->instRep;
  }

  bool terminator(void) {
    return this->is_terminator;
  }
  void set_terminator(void) {
    this->is_terminator = true;
  }

  void set_system_call_number(int cn) {
    this->system_call_number = cn;
  }
  int get_system_call_number() {
    return this->system_call_number;
  }
  bool has_system_call_number() {
    return this->system_call_number != -1;
  }

  void set_local_noreturn() {
    this->local_noreturn = true;
  }

  bool has_local_noreturn() {
    return this->local_noreturn;
  }

  uint8_t get_reloc_offset(CFGOpType op) {
    if (op == MEMRef) {
      return this->mem_reloc_offset;
    } else if (op == IMMRef) {
      return this->imm_reloc_offset;
    } else {
      return -1;
    }
  }

  void set_reloc_offset(CFGOpType op, uint8_t ro) {
    if (op == MEMRef) {
      this->mem_reloc_offset = ro;
    } else if (op == IMMRef) {
      this->imm_reloc_offset = ro;
    } else {
      //
    }
  }

  void set_reference(CFGOpType op, uint64_t ref) {
    if (op == MEMRef) {
      this->mem_reference = ref;
      this->has_mem_reference = true;
    } else if (op == IMMRef) {
      this->imm_reference = ref;
      this->has_imm_reference = true;
    } else {
      // void
    }
  }

  void set_ref_type(CFGOpType op, CFGRefType rt) {
    if (op == MEMRef) {
      this->mem_ref_type = rt;
    } else if (op == IMMRef) {
      this->imm_ref_type = rt;
    } else {
      // void
    }
  }

  void set_ref_reloc_type(CFGOpType op, uint64_t ref, uint64_t ro,
                          CFGRefType rt) {
    const char *ops = op == MEMRef ? "MEM" : "IMM";
    const char *rts = rt == CFGCodeRef ? "CODE" : "DATA";

    std::cout << __FUNCTION__ << ": Adding  ref: " << ops << ", to: "
              << std::hex << ref << ", ro: " << ro << ", rt: " << rts
              << std::endl;
    this->set_reference(op, ref);
    this->set_reloc_offset(op, ro);
    this->set_ref_type(op, rt);
  }

  bool has_reference(CFGOpType op) {
    if (op == MEMRef) {
      return this->has_mem_reference;
    } else if (op == IMMRef) {
      return this->has_imm_reference;
    } else {
      return false;
    }
  }

  uint64_t get_reference(CFGOpType op) {
    if (op == MEMRef) {
      return this->mem_reference;
    } else if (op == IMMRef) {
      return this->imm_reference;
    } else {
      return -1;
    }
  }

  CFGRefType get_ref_type(CFGOpType op) {
    if (op == MEMRef) {
      return this->mem_ref_type;
    } else if (op == IMMRef) {
      return this->imm_ref_type;
    } else {
      //TODO throw exception?
      //return -1;
      return this->mem_ref_type;
    }
  }

  bool has_code_ref() {
    if (this->has_mem_reference && this->mem_ref_type == CFGCodeRef) {
      return true;
    }

    if (this->has_imm_reference && this->imm_ref_type == CFGCodeRef) {
      return true;
    }

    return false;
  }

  bool get_is_call_external(void) {
    return this->is_call_external;
  }
  void set_is_call_external(void) {
    this->is_call_external = true;
  }

  llvm::MCInst get_inst(void) {
    return this->NativeInst;
  }
  void set_inst(const llvm::MCInst &i) {
    this->NativeInst = i;
  }
  void set_inst_rep(std::string s) {
    this->instRep = s;
  }

  VA get_loc(void) {
    return this->loc;
  }

  void set_tr(VA a) {
    this->tgtIfTrue = a;
  }
  void set_fa(VA a) {
    this->tgtIfFalse = a;
  }

  VA get_tr(void) {
    return this->tgtIfTrue;
  }
  VA get_fa(void) {
    return this->tgtIfFalse;
  }

  uint8_t get_len(void) {
    return this->len;
  }

  void set_call_tgt(VA addr) {
    this->targets.push_back(addr);
    return;
  }
  bool has_call_tgt() {
    return !this->targets.empty();
  }
  VA get_call_tgt(int index) {
    return this->targets.at(index);
  }

  void set_ext_call_target(ExternalCodeRefPtr t) {
    this->extCallTgt = t;
    this->ext_call_target = true;
    return;
  }

  void set_ext_data_ref(ExternalDataRefPtr t) {
    this->extDataRef = t;
    this->ext_data_ref = true;
    return;
  }

  bool has_ext_data_ref(void) {
    return this->ext_data_ref;
  }

  bool has_ext_call_target(void) {
    return this->ext_call_target;
  }

  bool has_external_ref(void) {
    return this->has_ext_call_target() || this->has_ext_data_ref();
  }

  bool has_rip_relative(void) {
    return this->hasRIP;
  }

  VA get_rip_relative(void) {
    return this->rip_target;
  }

  void set_rip_relative(unsigned i) {
    const llvm::MCOperand &base = NativeInst.getOperand(i + 0);
    const llvm::MCOperand &scale = NativeInst.getOperand(i + 1);
    const llvm::MCOperand &index = NativeInst.getOperand(i + 2);
    const llvm::MCOperand &disp = NativeInst.getOperand(i + 3);

    rip_target = loc + len + disp.getImm();
    //const
    this->hasRIP = true;
  }

  // accessors for JumpTable
  void set_jump_table(MCSJumpTablePtr p) {
    this->jump_table = true;
    this->jumpTable = p;
  }
  MCSJumpTablePtr get_jump_table(void) {
    return this->jumpTable;
  }
  bool has_jump_table(void) {
    return this->jump_table;
  }

  // accessors for JumpIndexTable
  void set_jump_index_table(JumpIndexTablePtr p) {
    this->jump_index_table = true;
    this->jumpIndexTable = p;
  }
  JumpIndexTablePtr get_jump_index_table(void) {
    return this->jumpIndexTable;
  }
  bool has_jump_index_table(void) {
    return this->jump_index_table;
  }

  Prefix get_prefix(void) {
    return this->pfx;
  }
  unsigned int get_addr_space(void) {

    switch (this->pfx) {
      case GSPrefix:
        return 256;
      case FSPrefix:
        return 257;
      default:
        return 0;
    }
  }

  unsigned int get_opcode(void) {
    return this->NativeInst.getOpcode();
  }

  ExternalCodeRefPtr get_ext_call_target(void) {
    return this->extCallTgt;
  }
  ExternalDataRefPtr get_ext_data_ref(void) {
    return this->extDataRef;
  }

  Inst(VA v, uint8_t l, const llvm::MCInst &inst, std::string instR, Prefix k,
       std::vector<uint8_t> bytes)
      : instBytes(bytes),
        tgtIfTrue(0),
        tgtIfFalse(0),
        loc(v),
        NativeInst(inst),
        instRep(instR),
        pfx(k),
        ext_call_target(false),
        is_call_external(false),
        is_terminator(false),
        imm_reloc_offset(0),
        imm_reference(0),
        imm_ref_type(CFGDataRef),
        has_imm_reference(false),
        mem_reloc_offset(0),
        mem_reference(0),
        mem_ref_type(CFGDataRef),
        has_mem_reference(false),
        len(l),
        jump_table(false),
        jump_index_table(false),
        ext_data_ref(false),
        arch(0),
        system_call_number( -1),
        local_noreturn(false),
        hasRIP(false),
        rip_target(0),
        offset_table( -1) {
  }
};

class NativeBlock {
 private:
  //a list of instructions
  VA baseAddr;
  std::list<InstPtr> instructions;
  std::list<VA> follows;
  llvm::MCInstPrinter *MyPrinter;
 public:
  NativeBlock(VA, llvm::MCInstPrinter *);
  void add_inst(InstPtr);
  VA get_base(void) {
    return this->baseAddr;
  }
  void add_follow(VA f) {
    this->follows.push_back(f);
  }
  std::list<VA> &get_follows(void) {
    return this->follows;
  }
  std::string print_block(void);
  std::string get_name(void);
  const std::list<InstPtr> &get_insts(void) {
    return this->instructions;
  }
  llvm::MCInstPrinter *get_printer(void) {
    return this->MyPrinter;
  }
  uint32_t get_size(void) {
    uint32_t blockLen = 0;

    for (std::list<InstPtr>::iterator i = this->instructions.begin();
        i != this->instructions.end(); ++i) {
      InstPtr inst = *i;
      blockLen += inst->get_len();
    }

    return blockLen;
  }
};

typedef boost::shared_ptr<NativeBlock> NativeBlockPtr;

class NativeFunction {
 public:
  NativeFunction(VA b)
      : funcEntryVA(b),
        nextBlockID(0),
        graph(nullptr) {
  }
  NativeFunction(VA b, const std::string &sym)
      : funcEntryVA(b),
        funcSymName(sym),
        nextBlockID(0),
        graph(nullptr) {
  }
  void add_block(NativeBlockPtr);
  VA get_start(void) {
    return this->funcEntryVA;
  }
  uint64_t num_blocks(void) {
    return this->IDtoBlock.size();
  }
  NativeBlockPtr block_from_id(uint64_t);
  NativeBlockPtr block_from_base(VA);
  uint64_t entry_block_id() const;
  void compute_graph(void);
  const CFG &get_cfg(void) {
    return *this->graph;
  }
  std::string get_name(void);
  const std::string &get_symbol_name(void);
 private:
  //a graph of blocks
  CFG *graph;
  //a map of block bases to block IDs
  std::map<VA, uint64_t> baseToID;
  //a map of block IDs to blocks
  std::map<uint64_t, NativeBlockPtr> IDtoBlock;
  //addr of function entry point
  VA funcEntryVA;
  std::string funcSymName;
  //next available block ID
  uint64_t nextBlockID;
};

typedef boost::shared_ptr<NativeBlock> NativeBlockPtr;
typedef boost::shared_ptr<NativeFunction> NativeFunctionPtr;

class DataSectionEntry {
 public:
  DataSectionEntry(uint64_t base, const std::vector<uint8_t>& b)
      : base(base),
        bytes(b),
        is_symbol(false) {
    //empty
  }

  DataSectionEntry(uint64_t base, const std::string& sname)
      : base(base),
        sym_name(sname),
        is_symbol(true) {

    this->bytes.push_back(0x0);
    this->bytes.push_back(0x0);
    this->bytes.push_back(0x0);
    this->bytes.push_back(0x0);
  }

  DataSectionEntry(uint64_t base, const std::string& sname,
                   uint64_t symbol_size)
      : base(base),
        sym_name(sname),
        is_symbol(true) {
    // initialize bytes to null
    for (unsigned int i = 0; i < symbol_size; i++) {
      this->bytes.push_back(0x0);
    }
  }

  uint64_t getBase() const {
    return this->base;
  }
  uint64_t getSize() const {
    return this->bytes.size();
  }
  std::vector<uint8_t> getBytes() const {
    return this->bytes;
  }

  bool getSymbol(std::string &sname) const {
    if (this->is_symbol) {
      sname = this->sym_name;
      return true;
    } else {
      return false;
    }
  }

  virtual ~DataSectionEntry() {
  }
  ;

 protected:
  uint64_t base;
  std::vector<uint8_t> bytes;
  bool is_symbol;
  std::string sym_name;
};

class DataSection {
 protected:
  std::list<DataSectionEntry> entries;
  uint64_t base;
  bool read_only;

 public:
  static const uint64_t NO_BASE = (uint64_t) ( -1);

  DataSection()
      : base(NO_BASE),
        read_only(false) {
  }

  virtual ~DataSection() {
  }
  ;

  void setReadOnly(bool isro) {
    this->read_only = isro;
  }
  bool isReadOnly() const {
    return this->read_only;
  }
  uint64_t getBase() const {
    return this->base;
  }

  std::list<DataSectionEntry>& getEntries() {
    return this->entries;
  }

  void addEntry(const DataSectionEntry &dse) {
    this->entries.push_back(dse);
    if (this->base == NO_BASE || this->base > dse.getBase()) {
      this->base = dse.getBase();
    }
  }

  uint64_t getSize() const {
    uint64_t size_sum = 0;
    for (std::list<DataSectionEntry>::const_iterator itr = entries.begin();
        itr != entries.end(); itr++) {
      size_sum += itr->getSize();
    }

    return size_sum;
  }
  std::vector<uint8_t> getBytes() const {
    std::vector<uint8_t> all_bytes;
    for (std::list<DataSectionEntry>::const_iterator itr = entries.begin();
        itr != entries.end(); itr++) {
      std::vector<uint8_t> vec = itr->getBytes();
      all_bytes.insert(all_bytes.end(), vec.begin(), vec.end());
    }

    return all_bytes;
  }
};

class NativeModule {
 public:
  class EntrySymbol {
   private:
    std::string name;
    VA addr;
    bool has_extra;
    int argc;
    bool does_return;
    ExternalCodeRef::CallingConvention cconv;

   public:
    EntrySymbol(const std::string &name, VA addr)
        : name(name),
          addr(addr),
          has_extra(false),
          argc(0),
          does_return(false),
          cconv(ExternalCodeRef::CallerCleanup) {
    }

    EntrySymbol(VA addr)
        : addr(addr),
          has_extra(false),
          argc(0),
          does_return(false),
          cconv(ExternalCodeRef::CallerCleanup) {
      this->name = "sub_" + to_string<VA>(this->addr, std::hex);
    }

    const std::string& getName() const {
      return this->name;
    }
    VA getAddr() const {
      return this->addr;
    }
    bool hasExtra() const {
      return this->has_extra;
    }
    int getArgc() const {
      return this->argc;
    }
    bool doesReturn() const {
      return this->does_return;
    }
    ExternalCodeRef::CallingConvention getConv() const {
      return this->cconv;
    }

    void setExtra(int argc, bool does_ret,
                  ExternalCodeRef::CallingConvention conv) {
      this->argc = argc;
      this->does_return = does_ret;
      this->cconv = conv;
      this->has_extra = true;
    }
  };

  NativeModule(std::string, std::list<NativeFunctionPtr>,
               llvm::MCInstPrinter *);
  void add_func(NativeFunctionPtr f) {
    this->funcs.push_back(f);
  }
  const std::list<NativeFunctionPtr> &get_funcs(void) {
    return this->funcs;
  }
  CFG get_cfg(void) {
    return this->callGraph;
  }
  std::string printModule(void);
  std::string name(void) {
    return this->nameStr;
  }
  llvm::MCInstPrinter *get_printer(void) {
    return this->MyPrinter;
  }

  //add a data section from a COFF object
  void addDataSection(VA, std::vector<uint8_t> &);
  void addDataSection(const DataSection &d);
  std::list<DataSection> &getData(void) {
    return this->dataSecs;
  }

  //add an external reference
  void addExtCall(ExternalCodeRefPtr p) {
    this->extCalls.push_back(p);
    return;
  }
  const std::list<ExternalCodeRefPtr> &getExtCalls(void) {
    return this->extCalls;
  }

  //external data ref
  void addExtDataRef(ExternalDataRefPtr p) {
    this->extData.push_back(p);
    return;
  }
  const std::list<ExternalDataRefPtr> &getExtDataRefs(void) {
    return this->extData;
  }

  std::vector<EntrySymbol> entries;

  const std::vector<EntrySymbol> &getEntryPoints() const {
    return this->entries;
  }
  void addEntryPoint(const EntrySymbol& ep) {
    this->entries.push_back(ep);
  }

  void setTarget(const llvm::Target *T) {
    this->target = T;
  }

  void setTargetTriple(const std::string &triple) {
    this->triple = llvm::Triple(triple);
  }

  bool is64Bit(void) {
    if (std::string(target->getName()) == "x86-64") {
      return true;
    }
    return false;
  }

  void addOffsetTables(const std::list<MCSOffsetTablePtr> & tables);

 private:
  std::list<NativeFunctionPtr> funcs;
  std::map<FuncID, NativeFunctionPtr> IDtoFunc;
  CFG callGraph;
  FuncID nextID;
  std::string nameStr;
  llvm::MCInstPrinter *MyPrinter;
  const llvm::Target *target;
  llvm::Triple triple;

  std::list<DataSection> dataSecs;
  std::list<ExternalCodeRefPtr> extCalls;
  std::list<ExternalDataRefPtr> extData;

 public:
  std::unordered_map<VA, MCSOffsetTablePtr> offsetTables;

};

typedef boost::shared_ptr<NativeModule> NativeModulePtr;

enum ModuleInputFormat {
  COFFObject,
  PEFile,
  ASMText,
  ProtoBuff
};

const llvm::Target *findDisTarget(std::string);
NativeModulePtr readModule(std::string, ModuleInputFormat, std::list<VA>,
                           const llvm::Target*);

// used in testSemantics.cpp via funcFromBuff
NativeBlockPtr blockFromBuff(VA, BufferMemoryObject &,
                             const llvm::MCDisassembler *,
                             llvm::MCInstPrinter *);

// used in testSemantics.cpp
NativeFunctionPtr funcFromBuff(VA, BufferMemoryObject &,
                               const llvm::MCDisassembler *,
                               llvm::MCInstPrinter *);

void addExterns(std::list<NativeFunctionPtr>, NativeModulePtr);

std::string dumpProtoBuf(NativeModulePtr);

#endif
