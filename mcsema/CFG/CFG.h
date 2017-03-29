/*
Copyright (c) 2017, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of the organization nor the names of its
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

#ifndef MCSEMA_CFG_CFG_H_
#define MCSEMA_CFG_CFG_H_

#include <stack>
#include <set>
#include <map>
#include <memory>
#include <list>
#include <unordered_map>

#include <cstdio>
#include <cstdint>
#include <iostream>

#include <llvm/ADT/Triple.h>

#include "mcsema/CFG/Externals.h"

namespace llvm {
class Target;
}  // namespace llvm

namespace mcsema {

typedef uint64_t VA;

class NativeInst;
typedef NativeInst *NativeInstPtr;

class ExternalCodeRef;
class ExternalDataRef;
class MCSJumpTable;
class JumpIndexTable;
class MCSOffsetTable;

typedef ExternalCodeRef *ExternalCodeRefPtr;
typedef ExternalDataRef *ExternalDataRefPtr;
typedef MCSJumpTable *MCSJumpTablePtr;
typedef JumpIndexTable *JumpIndexTablePtr;
typedef MCSOffsetTable *MCSOffsetTablePtr;


/* we're going to make some assumptions about external calls:
 *  - they have some sane calling convention
 *  - they take a defined number of arguments
 *  - they either return no values and have no effects on local
 registers, or, they return a single integer value and
 assign that value to the EAX register
 */

struct NativeRef {
  ExternalCodeRefPtr code;
  ExternalDataRefPtr data;
};

class NativeInst {
 private:
  std::vector<VA> targets;
  VA tgtIfTrue;
  VA tgtIfFalse;
  VA loc;
  std::string bytes;

 public:
  ExternalCodeRefPtr external_code_ref;
  VA code_addr;

  ExternalDataRefPtr external_mem_data_ref;
  ExternalCodeRefPtr external_mem_code_ref;

  ExternalDataRefPtr external_disp_data_ref;
  ExternalCodeRefPtr external_disp_code_ref;

  ExternalDataRefPtr external_imm_data_ref;
  ExternalCodeRefPtr external_imm_code_ref;

  VA mem_ref_data_addr;
  VA mem_ref_code_addr;

  VA disp_ref_data_addr;
  VA disp_ref_code_addr;

  VA imm_ref_data_addr;
  VA imm_ref_code_addr;

 private:
  MCSJumpTablePtr jumpTable;
  bool jump_table;
  JumpIndexTablePtr jumpIndexTable;
  bool jump_index_table;

  size_t len;
  bool is_terminator;

  //  if this instruction is a system call, its system call number
  //  otherwise, -1
  int system_call_number;
  bool local_noreturn;
 public:
  VA offset_table;

  bool terminator(void) const;
  void set_terminator(void);

  void set_system_call_number(int cn);
  int get_system_call_number(void) const;
  bool has_system_call_number(void) const;

  void set_local_noreturn(void);
  bool has_local_noreturn(void) const;

  VA get_loc(void) const;

  const std::string &get_bytes(void) const;

  void set_tr(VA a);
  void set_fa(VA a);

  VA get_tr(void) const;
  VA get_fa(void) const;

  size_t get_len(void) const;

  // accessors for JumpTable
  void set_jump_table(MCSJumpTablePtr p);
  MCSJumpTablePtr get_jump_table(void) const;
  bool has_jump_table(void) const;

  // accessors for JumpIndexTable
  void set_jump_index_table(JumpIndexTablePtr p);
  JumpIndexTablePtr get_jump_index_table(void) const;
  bool has_jump_index_table(void) const;

  NativeInst(VA v, const std::string &bytes_);
};

class NativeBlock {
 private:
  // A list of instructions
  VA baseAddr;
  std::list<NativeInstPtr> instructions;
  std::set<VA> follows;

 public:
  explicit NativeBlock(VA);
  void add_inst(NativeInstPtr);
  VA get_base(void);
  void add_follow(VA f);
  std::set<VA> &get_follows(void);
  std::string get_name(void);
  const std::list<NativeInstPtr> &get_insts(void);

 private:
  NativeBlock(void) = delete;
};

typedef NativeBlock *NativeBlockPtr;

class NativeFunction {
 public:
  explicit NativeFunction(VA b)
      : funcEntryVA(b) {}

  NativeFunction(VA b, const std::string &sym)
      : funcEntryVA(b),
        funcSymName(sym) {}

  void add_block(NativeBlockPtr);

  VA get_start(void);
  uint64_t num_blocks(void);
  NativeBlockPtr block_from_base(VA);
  const std::map<VA, NativeBlockPtr> &get_blocks(void) const;
  std::string get_name(void);
  const std::string &get_symbol_name(void);

 private:
  NativeFunction(void) = delete;

  // Use a `std::map` to keep the blocks in their original order.
  std::map<VA, NativeBlockPtr> blocks;

  // Addr of function entry point
  VA funcEntryVA;

  std::string funcSymName;
};

typedef NativeBlock *NativeBlockPtr;
typedef NativeFunction *NativeFunctionPtr;

class DataSectionEntry {
 public:
  DataSectionEntry(uint64_t base, const std::vector<uint8_t> &b);
  DataSectionEntry(uint64_t base, const std::string &sname);
  DataSectionEntry(uint64_t base, const std::string &sname,
                   uint64_t symbol_size);

  uint64_t getBase(void) const;

  uint64_t getSize(void) const;

  const std::vector<uint8_t> &getBytes(void) const;

  bool getSymbol(std::string &sname) const;

  virtual ~DataSectionEntry(void);

 protected:
  uint64_t base;
  std::vector<uint8_t> bytes;
  bool is_symbol;
  std::string sym_name;

 private:
  DataSectionEntry(void) = delete;
};

class DataSection {
 protected:
  std::list<DataSectionEntry> entries;
  uint64_t base;
  bool read_only;

 public:
  static constexpr uint64_t NO_BASE = ~0ULL;

  DataSection(void);
  virtual ~DataSection(void);

  void setReadOnly(bool isro);
  bool isReadOnly(void) const;
  uint64_t getBase(void) const;
  const std::list<DataSectionEntry> &getEntries(void) const;
  void addEntry(const DataSectionEntry &dse);
  uint64_t getSize(void) const;
  std::vector<uint8_t> getBytes(void) const;
};

class NativeEntrySymbol {
 private:
  const VA addr;
  std::string name;
  bool has_extra;
  int num_args;
  bool does_return;
  ExternalCodeRef::CallingConvention calling_conv;

 public:
  NativeEntrySymbol(const std::string &name_, VA addr_);
  explicit NativeEntrySymbol(VA addr_);

  const std::string &getName(void) const;
  VA getAddr(void) const;
  bool hasExtra(void) const;
  void setExtra(int argc_, bool does_ret,
                ExternalCodeRef::CallingConvention conv);
  int getArgc(void) const;
  bool doesReturn(void) const;
  ExternalCodeRef::CallingConvention getConv(void) const;

 private:
  NativeEntrySymbol(void) = delete;
};

class NativeModule {
 public:
  NativeModule(const std::string &module_name_,
               const std::unordered_map<VA, NativeFunctionPtr> &funcs_,
               const std::string &triple_);

  void add_func(NativeFunctionPtr f);
  const std::unordered_map<VA, NativeFunctionPtr> &get_funcs(void) const;

  const std::string &name(void) const;

  //add a data section from a COFF object
  void addDataSection(VA, std::vector<uint8_t> &);
  void addDataSection(const DataSection &d);

  const std::list<DataSection> &getData(void) const;

  //add an external reference
  void addExtCall(ExternalCodeRefPtr p);

  const std::list<ExternalCodeRefPtr> &getExtCalls(void) const;

  //external data ref
  void addExtDataRef(ExternalDataRefPtr p);

  const std::list<ExternalDataRefPtr> &getExtDataRefs(void) const;

  const std::vector<NativeEntrySymbol> &getEntryPoints(void) const;

  void addEntryPoint(const NativeEntrySymbol &ep);

  bool is64Bit(void) const;

  void addOffsetTables(const std::list<MCSOffsetTablePtr> &tables);

  std::vector<NativeEntrySymbol> entries;

 private:
  NativeModule(void) = delete;

  std::unordered_map<VA, NativeFunctionPtr> funcs;
  const std::string module_name;
  const llvm::Triple triple;

  std::list<DataSection> data_sections;
  std::list<ExternalCodeRefPtr> external_code_refs;
  std::list<ExternalDataRefPtr> external_data_refs;

 public:
  std::unordered_map<VA, MCSOffsetTablePtr> offset_tables;
};

typedef NativeModule *NativeModulePtr;

enum ModuleInputFormat {
  COFFObject,
  PEFile,
  ASMText,
  ProtoBuff
};

NativeModulePtr ReadProtoBuf(const std::string &file_name);

}  // namespace mcsema

#endif  // MCSEMA_CFG_CFG_H_
