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

#include <glog/logging.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <utility>

#include "generated/CFG.pb.h"  // Auto-generated.

#include "mcsema/Arch/Arch.h"
#include "mcsema/CFG/CFG.h"

#include "mcsema/cfgToLLVM/TransExcn.h"

#include "mcsema/CFG/Externals.h"
#include "mcsema/cfgToLLVM/JumpTables.h"

namespace mcsema {

bool NativeInst::terminator(void) const {
  LOG(FATAL)
      << "Not yet reimplemented";
  return this->is_terminator;
}

void NativeInst::set_terminator(void) {
  LOG(FATAL)
      << "Not yet reimplemented";
  this->is_terminator = true;
}

void NativeInst::set_system_call_number(int cn) {
  this->system_call_number = cn;
}

int NativeInst::get_system_call_number(void) const {
  return this->system_call_number;
}

bool NativeInst::has_system_call_number(void) const {
  return this->system_call_number != -1;
}

void NativeInst::set_local_noreturn(void) {
  this->local_noreturn = true;
}

bool NativeInst::has_local_noreturn(void) const {
  return this->local_noreturn;
}

uint8_t NativeInst::get_reloc_offset(CFGOpType op) const {
  if (op == MEMRef) {
    return this->mem_reloc_offset;
  } else if (op == IMMRef) {
    return this->imm_reloc_offset;
  } else {
    return -1;
  }
}

void NativeInst::set_reloc_offset(CFGOpType op, uint8_t ro) {
  if (op == MEMRef) {
    this->mem_reloc_offset = ro;
  } else if (op == IMMRef) {
    this->imm_reloc_offset = ro;
  } else {
    //
  }
}

void NativeInst::set_reference(CFGOpType op, uint64_t ref) {
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

void NativeInst::set_ref_type(CFGOpType op, CFGRefType rt) {
  if (op == MEMRef) {
    this->mem_ref_type = rt;
  } else if (op == IMMRef) {
    this->imm_ref_type = rt;
  } else {
    // void
  }
}

void NativeInst::set_ref_reloc_type(CFGOpType op, uint64_t ref, uint64_t ro,
                              CFGRefType rt) {
  const char *ops = op == MEMRef ? "MEM" : "IMM";
  const char *rts = rt == CFGCodeRef ? "CODE" : "DATA";

  LOG(INFO)
      << ": Adding ref: " << ops << ", to: " << std::hex
      << ref << ", ro: " << ro << ", rt: " << rts;
  this->set_reference(op, ref);
  this->set_reloc_offset(op, ro);
  this->set_ref_type(op, rt);
}

bool NativeInst::has_reference(CFGOpType op) const {
  if (op == MEMRef) {
    return this->has_mem_reference;
  } else if (op == IMMRef) {
    return this->has_imm_reference;
  } else {
    return false;
  }
}

uint64_t NativeInst::get_reference(CFGOpType op) const {
  if (op == MEMRef) {
    return this->mem_reference;
  } else if (op == IMMRef) {
    return this->imm_reference;
  } else {
    return -1;
  }
}

NativeInst::CFGRefType NativeInst::get_ref_type(CFGOpType op) const {
  if (op == MEMRef) {
    return this->mem_ref_type;
  } else {
    return this->imm_ref_type;
  }
}

bool NativeInst::has_code_ref(void) const {
  if (this->has_mem_reference && this->mem_ref_type == CFGCodeRef) {
    return true;
  }

  if (this->has_imm_reference && this->imm_ref_type == CFGCodeRef) {
    return true;
  }

  return false;
}

bool NativeInst::get_is_call_external(void) const {
  return this->is_call_external;
}

void NativeInst::set_is_call_external(void) {
  this->is_call_external = true;
}

VA NativeInst::get_loc(void) const {
  return this->loc;
}

const std::string &NativeInst::get_bytes(void) const {
  return this->bytes;
}

void NativeInst::set_tr(VA a) {
  this->tgtIfTrue = a;
}

void NativeInst::set_fa(VA a) {
  this->tgtIfFalse = a;
}

VA NativeInst::get_tr(void) const {
  LOG(FATAL)
      << "Not yet reimplemented";
  return this->tgtIfTrue;
}

VA NativeInst::get_fa(void) const {
  LOG(FATAL)
      << "Not yet reimplemented";
  return this->tgtIfFalse;
}

uint8_t NativeInst::get_len(void) const {
  return this->len;
}

void NativeInst::set_ext_call_target(ExternalCodeRefPtr t) {
  this->extCallTgt = t;
  this->ext_call_target = true;
  return;
}

void NativeInst::set_ext_data_ref(ExternalDataRefPtr t) {
  this->extDataRef = t;
  this->ext_data_ref = true;
  return;
}

bool NativeInst::has_ext_data_ref(void) const {
  return this->ext_data_ref;
}

bool NativeInst::has_ext_call_target(void) const {
  return this->ext_call_target;
}

bool NativeInst::has_external_ref(void) const {
  return this->has_ext_call_target() || this->has_ext_data_ref();
}

// accessors for JumpTable
void NativeInst::set_jump_table(MCSJumpTablePtr p) {
  this->jump_table = true;
  this->jumpTable = p;
}

MCSJumpTablePtr NativeInst::get_jump_table(void) const {
  return this->jumpTable;
}

bool NativeInst::has_jump_table(void) const {
  return this->jump_table;
}

// accessors for JumpIndexTable
void NativeInst::set_jump_index_table(JumpIndexTablePtr p) {
  this->jump_index_table = true;
  this->jumpIndexTable = p;
}

JumpIndexTablePtr NativeInst::get_jump_index_table(void) const {
  return this->jumpIndexTable;
}

bool NativeInst::has_jump_index_table(void) const {
  return this->jump_index_table;
}

NativeInst::Prefix NativeInst::get_prefix(void) const {
  LOG(FATAL)
      << "Not yet reimplemented, probably unnecessary.";
  return this->pfx;
}

unsigned int NativeInst::get_addr_space(void) const {
  if (this->pfx == NativeInst::FSPrefix) {
    return 257;
  } else if (this->pfx == NativeInst::GSPrefix) {
    return 256;
  } else {
    return 0;
  }
}

ExternalCodeRefPtr NativeInst::get_ext_call_target(void) const {
  return this->extCallTgt;
}
ExternalDataRefPtr NativeInst::get_ext_data_ref(void) const {
  return this->extDataRef;
}

NativeInst::NativeInst(VA v, const std::string &bytes_)
    : tgtIfTrue(0),
      tgtIfFalse(0),
      loc(v),
      bytes(bytes_),
      extCallTgt(nullptr),
      extDataRef(nullptr),
      jumpTable(nullptr),
      jump_table(false),
      jumpIndexTable(nullptr),
      jump_index_table(false),
      pfx(NoPrefix),
      ext_call_target(false),
      ext_data_ref(false),
      is_call_external(false),
      len(bytes.size()),
      is_terminator(false),
      imm_reloc_offset(0),
      imm_reference(0),
      imm_ref_type(CFGDataRef),
      has_imm_reference(false),
      mem_reloc_offset(0),
      mem_reference(0),
      mem_ref_type(CFGDataRef),
      has_mem_reference(false),
      system_call_number(-1),
      local_noreturn(false),
      offset_table(-1) {}

DataSectionEntry::DataSectionEntry(uint64_t base, const std::vector<uint8_t> &b)
    : base(base),
      bytes(b),
      is_symbol(false) {}

DataSectionEntry::DataSectionEntry(uint64_t base, const std::string &sname)
    : base(base),
      is_symbol(true),
      sym_name(sname) {

  this->bytes.push_back(0x0);
  this->bytes.push_back(0x0);
  this->bytes.push_back(0x0);
  this->bytes.push_back(0x0);
}

DataSectionEntry::DataSectionEntry(uint64_t base, const std::string &sname,
                                   uint64_t symbol_size)
    : base(base),
      bytes(symbol_size),
      is_symbol(true),
      sym_name(sname) {}

uint64_t DataSectionEntry::getBase(void) const {
  return this->base;
}

uint64_t DataSectionEntry::getSize(void) const {
  return this->bytes.size();
}

const std::vector<uint8_t> &DataSectionEntry::getBytes(void) const {
  return this->bytes;
}

bool DataSectionEntry::getSymbol(std::string &sname) const {
  if (this->is_symbol) {
    sname = this->sym_name;
    return true;
  } else {
    return false;
  }
}

DataSectionEntry::~DataSectionEntry(void) {}

DataSection::DataSection(void)
    : base(NO_BASE),
      read_only(false) {}

DataSection::~DataSection(void) {}

void DataSection::setReadOnly(bool isro) {
  this->read_only = isro;
}

bool DataSection::isReadOnly(void) const {
  return this->read_only;
}

uint64_t DataSection::getBase(void) const {
  return this->base;
}

const std::list<DataSectionEntry> &DataSection::getEntries(void) const {
  return this->entries;
}

void DataSection::addEntry(const DataSectionEntry &dse) {
  this->entries.push_back(dse);
  if (this->base == NO_BASE || this->base > dse.getBase()) {
    this->base = dse.getBase();
  }
}

uint64_t DataSection::getSize(void) const {
  uint64_t size_sum = 0;
  for (std::list<DataSectionEntry>::const_iterator itr = entries.begin();
      itr != entries.end(); itr++) {
    size_sum += itr->getSize();
  }
  return size_sum;
}

std::vector<uint8_t> DataSection::getBytes(void) const {
  std::vector<uint8_t> all_bytes;
  for (const auto entry : entries) {
    const auto &vec = entry.getBytes();
    all_bytes.insert(all_bytes.end(), vec.begin(), vec.end());
  }
  return all_bytes;
}

NativeEntrySymbol::NativeEntrySymbol(const std::string &name_, VA addr_)
    : addr(addr_),
      name(name_),
      has_extra(false),
      num_args(0),
      does_return(false),
      calling_conv(ExternalCodeRef::CallerCleanup) {}

NativeEntrySymbol::NativeEntrySymbol(VA addr_)
    : addr(addr_),
      has_extra(false),
      num_args(0),
      does_return(false),
      calling_conv(ExternalCodeRef::CallerCleanup) {
  std::stringstream ss;
  ss << "sub_" << std::hex << this->addr;
  this->name = ss.str();
}

const std::string &NativeEntrySymbol::getName(void) const {
  return this->name;
}

VA NativeEntrySymbol::getAddr(void) const {
  return this->addr;
}

bool NativeEntrySymbol::hasExtra(void) const {
  return this->has_extra;
}

int NativeEntrySymbol::getArgc(void) const {
  return this->num_args;
}

bool NativeEntrySymbol::doesReturn(void) const {
  return this->does_return;
}

ExternalCodeRef::CallingConvention NativeEntrySymbol::getConv(void) const {
  return this->calling_conv;
}

void NativeEntrySymbol::setExtra(int argc_, bool does_ret,
                                 ExternalCodeRef::CallingConvention conv) {
  this->num_args = argc_;
  this->does_return = does_ret;
  this->calling_conv = conv;
  this->has_extra = true;
}

NativeModule::NativeModule(
    const std::string &module_name_,
    const std::unordered_map<VA, NativeFunctionPtr> &funcs_,
    const std::string &triple_)
    : funcs(funcs_),
      module_name(module_name_),
      triple(triple_) {}

VA NativeFunction::get_start(void) {
  return this->funcEntryVA;
}

uint64_t NativeFunction::num_blocks(void) {
  return this->blocks.size();
}

const std::map<VA, NativeBlockPtr> &NativeFunction::get_blocks(void) const {
  return this->blocks;
}

NativeBlockPtr NativeFunction::block_from_base(VA base) {
  auto block_it = blocks.find(base);
  CHECK(block_it != blocks.end())
      << "Could not find block at address " << std::hex << base;
  return block_it->second;
}

NativeBlock::NativeBlock(VA b)
    : baseAddr(b) {}

void NativeBlock::add_inst(NativeInstPtr p) {
  this->instructions.push_back(p);
}

VA NativeBlock::get_base(void) {
  return this->baseAddr;
}

void NativeBlock::add_follow(VA f) {
  this->follows.push_back(f);
}

std::list<VA> &NativeBlock::get_follows(void) {
  return this->follows;
}

const std::list<NativeInstPtr> &NativeBlock::get_insts(void) {
  return this->instructions;
}

void NativeFunction::add_block(NativeBlockPtr b) {
  auto blockBase = b->get_base();
  CHECK(!this->blocks.count(blockBase))
      << "Added duplicate block for address " << std::hex << blockBase;
  this->blocks[blockBase] = b;
}

std::string NativeFunction::get_name(void) {
  std::stringstream ss;
  ss << "sub_" << std::hex << this->funcEntryVA;
  return ss.str();
}

const std::string &NativeFunction::get_symbol_name(void) {
  return this->funcSymName;
}

std::string NativeBlock::get_name(void) {
  std::stringstream ss;
  ss << "block_" << std::hex << this->baseAddr;
  return ss.str();
}

void NativeModule::addDataSection(VA base, std::vector<uint8_t> &bytes) {

  DataSection ds;
  DataSectionEntry dse(base, bytes);
  ds.addEntry(dse);

  this->data_sections.push_back(ds);
}

void NativeModule::addDataSection(const DataSection &d) {
  this->data_sections.push_back(d);
}

void NativeModule::add_func(NativeFunctionPtr f) {
  this->funcs[f->get_start()] = f;
}

const std::unordered_map<VA, NativeFunctionPtr> &NativeModule::get_funcs(
    void) const {
  return this->funcs;
}

const std::string &NativeModule::name(void) const {
  return this->module_name;
}

const std::list<DataSection> &NativeModule::getData(void) const {
  return this->data_sections;
}

void NativeModule::addExtCall(ExternalCodeRefPtr p) {
  this->external_code_refs.push_back(p);
}

const std::list<ExternalCodeRefPtr> &NativeModule::getExtCalls(void) const {
  return this->external_code_refs;
}

void NativeModule::addExtDataRef(ExternalDataRefPtr p) {
  this->external_data_refs.push_back(p);
}

const std::list<ExternalDataRefPtr> &NativeModule::getExtDataRefs(void) const {
  return this->external_data_refs;
}

const std::vector<NativeEntrySymbol> &NativeModule::getEntryPoints(void) const {
  return this->entries;
}

void NativeModule::addEntryPoint(const NativeEntrySymbol &ep) {
  this->entries.push_back(ep);
}

bool NativeModule::is64Bit(void) const {
  return 64 == ArchAddressSize();
}

void NativeModule::addOffsetTables(
    const std::list<MCSOffsetTablePtr> & tables) {

  for (const auto &table : tables) {
    LOG(INFO)
        << "Adding offset table at " << std::hex << table->getStartAddr();
    this->offset_tables.insert({table->getStartAddr(), table});
  }
}

NativeInst::CFGRefType deserRefType(::Instruction::RefType k) {
  switch (k) {
    case ::Instruction::CodeRef:
      return NativeInst::CFGCodeRef;
    case ::Instruction::DataRef:
      return NativeInst::CFGDataRef;
    default:
      LOG(FATAL)
          << "Unsupported reference type";
      return NativeInst::CFGInvalidRef;
  }
}

static ExternalCodeRefPtr getExternal(
    const std::string &s, const std::list<ExternalCodeRefPtr> &extcode) {
  for (auto e : extcode) {
    if (s == e->getSymbolName()) {
      return e;
    }
  }
  return ExternalCodeRefPtr();
}

enum : size_t {
  kMaxNumInstrBytes = 16ULL  // 15 on x86 and amd64.
};

static NativeInstPtr DeserializeInst(
    const ::Instruction &inst,
    const std::list<ExternalCodeRefPtr> &extcode) {
  VA addr = inst.inst_addr();
  auto tr_tgt = static_cast<VA>(inst.true_target());
  auto fa_tgt = static_cast<VA>(inst.false_target());

  NativeInstPtr ip = new NativeInst(addr, inst.inst_bytes());
  if (!ip) {
    LOG(ERROR)
        << "Unable to deserialize instruction at " << std::hex << addr;
    return nullptr;
  }

  if (tr_tgt) {
    ip->set_tr(tr_tgt);
  }

  if (fa_tgt) {
    ip->set_fa(fa_tgt);
  }

  if (inst.has_ext_call_name()) {
    ExternalCodeRefPtr p = getExternal(inst.ext_call_name(), extcode);
    if (!p) {
      LOG(ERROR)
          << "Unable to find external call " << inst.ext_call_name()
          << " for inst at " << std::hex << addr;
      return nullptr;
    }
    ip->set_ext_call_target(p);
  }

  if (inst.has_ext_data_name()) {
    ExternalDataRefPtr p(new ExternalDataRef(inst.ext_data_name()));
    ip->set_ext_data_ref(p);
  }

  if (inst.has_imm_reference()) {
    auto ref = static_cast<uint64_t>(inst.imm_reference());
    uint64_t ro = 0;
    auto rt = NativeInst::CFGInvalidRef;

    if (inst.has_imm_reloc_offset()) {
      ro = static_cast<VA>(inst.imm_reloc_offset());
    }

    if (inst.has_imm_ref_type()) {
      rt = deserRefType(inst.imm_ref_type());
    }

    ip->set_ref_reloc_type(NativeInst::IMMRef, ref, ro, rt);
  }

  if (inst.has_mem_reference()) {
    uint64_t ref = inst.mem_reference();
    uint64_t ro = 0;
    auto rt = NativeInst::CFGInvalidRef;

    if (inst.has_mem_reloc_offset()) {
      ro = inst.mem_reloc_offset();
    }

    if (inst.has_mem_ref_type()) {
      rt = deserRefType(inst.mem_ref_type());
    }

    ip->set_ref_reloc_type(NativeInst::MEMRef, ref, ro, rt);
  }

  if (inst.has_jump_table()) {
    // create new jump table

    const ::JumpTbl &jmp_tbl = inst.jump_table();
    std::vector<VA> table_entries;

    for (int i = 0; i < jmp_tbl.table_entries_size(); i++) {
      table_entries.push_back(jmp_tbl.table_entries(i));
    }

    VA data_offset = ~0ULL;
    if (jmp_tbl.has_offset_from_data()) {
      data_offset = jmp_tbl.offset_from_data();
    }
    auto jmp = new MCSJumpTable(table_entries, jmp_tbl.zero_offset(),
                                data_offset);
    ip->set_jump_table(MCSJumpTablePtr(jmp));
  }

  if (inst.has_jump_index_table()) {
    // create new jump table

    const ::JumpIndexTbl &idx_tbl = inst.jump_index_table();
    const auto &serialized_tbl = idx_tbl.table_entries();
    std::vector<uint8_t> tbl_bytes(serialized_tbl.begin(),
                                   serialized_tbl.end());

    auto idx = new JumpIndexTable(tbl_bytes, idx_tbl.zero_offset());
    ip->set_jump_index_table(JumpIndexTablePtr(idx));
  }

  if (inst.has_system_call_number()) {
    ip->set_system_call_number(inst.system_call_number());
  }

  if (inst.has_local_noreturn()) {
    ip->set_local_noreturn();
  }

  if (inst.has_offset_table_addr()) {
    ip->offset_table = inst.offset_table_addr();
  }

  return ip;
}

static NativeBlockPtr DeserializeBlock(
    const ::Block &block,
    const std::list<ExternalCodeRefPtr> &extcode) {

  auto block_va = static_cast<VA>(block.base_address());
  NativeBlockPtr natB = NativeBlockPtr(new NativeBlock(block_va));

  for (auto &inst : block.insts()) {
    auto native_inst = DeserializeInst(inst, extcode);
    if (!native_inst) {
      LOG(INFO)
          << "Unable to deserialize block at " << std::hex << block_va;
      return nullptr;
    }
    natB->add_inst(native_inst);
  }

  /* add the follows */
  for (auto &succ : block.block_follows()) {
    natB->add_follow(succ);
  }

  return natB;
}

static NativeFunctionPtr DeserializeNativeFunc(
    const ::Function &func,
    const std::list<ExternalCodeRefPtr> &extcode) {

  NativeFunction *nf = nullptr;
  if (func.has_symbol_name() && !func.symbol_name().empty()) {
    nf = new NativeFunction(func.entry_address(), func.symbol_name());
  } else {
    nf = new NativeFunction(func.entry_address());
  }

  // Read all the blocks from this function
  for (auto &block : func.blocks()) {
    auto native_block = DeserializeBlock(block, extcode);
    if (!native_block) {
      LOG(ERROR)
          << "Unable to deserialize function at " << std::hex
          << func.entry_address();
      return nullptr;
    }
    nf->add_block(native_block);
  }

  return NativeFunctionPtr(nf);
}

static ExternalCodeRef::CallingConvention DeserializeCallingConvention(
    ::ExternalFunction::CallingConvention k) {
  switch (k) {
    case ::ExternalFunction::CallerCleanup:
      return ExternalCodeRef::CallerCleanup;

    case ::ExternalFunction::CalleeCleanup:
      return ExternalCodeRef::CalleeCleanup;

    case ::ExternalFunction::FastCall:
      return ExternalCodeRef::FastCall;

    case ::ExternalFunction::McsemaCall:
      return ExternalCodeRef::McsemaCall;

    default:
      LOG(FATAL)
          << "Unsupported calling covention.";
  }
}

static ExternalCodeRefPtr DeserializeExternFunc(const ::ExternalFunction &f) {
  auto c = DeserializeCallingConvention(f.calling_convention());
  const auto &symName = f.symbol_name();
  ExternalCodeRef::ReturnType retTy;
  auto argCount = f.argument_count();

  if (f.has_return()) {
    retTy = ExternalCodeRef::IntTy;
  } else {
    retTy = ExternalCodeRef::VoidTy;
  }

  if (f.no_return()) {
    retTy = ExternalCodeRef::NoReturn;
  }

  ExternalCodeRefPtr ext = ExternalCodeRefPtr(
      new ExternalCodeRef(symName, argCount, c, retTy));
  ext->setWeak(f.is_weak());

  return ext;
}

static ExternalDataRefPtr DeserializeExternData(const ::ExternalData &ed) {
  ExternalDataRefPtr ext = ExternalDataRefPtr(
      new ExternalDataRef(ed.symbol_name(),
                          static_cast<size_t>(ed.data_size())));
  ext->setWeak(ed.is_weak());
  return ext;
}

static DataSectionEntry DeserializeDataSymbol(const ::DataSymbol &ds) {
  LOG(INFO)
      << "Deserializing symbol at: " << std::hex << ds.base_address() << ", "
      << ds.symbol_name() << ", " << ds.symbol_size();

  return DataSectionEntry(
      ds.base_address(), ds.symbol_name(), ds.symbol_size());
}

static DataSectionEntry makeDSEBlob(const std::vector<uint8_t> &bytes,
                                    uint64_t start,  // offset in bytes vector
    uint64_t end,  // offset in bytes vector
    uint64_t base_va) {  // virtual address these bytes are based at
  std::vector<uint8_t> blob_bytes(bytes.begin() + (start),
                                  bytes.begin() + (end));
  return DataSectionEntry(base_va, blob_bytes);
}

static void DeserializeData(const ::Data &d, DataSection &ds) {
  const auto &dt = d.data();
  std::vector<uint8_t> bytes(dt.begin(), dt.end());
  uint64_t base_address = d.base_address();
  uint64_t cur_pos = base_address;

  ds.setReadOnly(d.read_only());

  // assumes symbols are in-order
  for (int i = 0; i < d.symbols_size(); i++) {
    DataSectionEntry dse_sym = DeserializeDataSymbol(d.symbols(i));
    auto dse_base = dse_sym.getBase();

    LOG(INFO)
        << "cur_pos: " << std::hex << cur_pos
        << ", dse_base: " << std::hex << dse_base;

    // symbol next to blob
    if (dse_base > cur_pos) {
      ds.addEntry(
          makeDSEBlob(bytes, cur_pos - base_address, dse_base - base_address,
                      cur_pos));
      ds.addEntry(dse_sym);

      cur_pos = dse_base + dse_sym.getSize();
      LOG(INFO)
          << "new_cur_pos: " << std::hex << cur_pos;

      // symbols next to each other
    } else if (dse_base == cur_pos) {
      ds.addEntry(dse_sym);
      cur_pos = dse_base + dse_sym.getSize();
      LOG(INFO)
          << "new_cur_pos2: " << std::hex << cur_pos;

    } else {
      LOG(FATAL)
          << "Deserialized an out-of-order symbol!";
    }
  }

  // there is a data blob after the last symbol
  // or there are no symbols
  if (cur_pos < base_address + bytes.size()) {
    ds.addEntry(
        makeDSEBlob(bytes, cur_pos - base_address, bytes.size(), cur_pos));
  }
}

NativeModulePtr ReadProtoBuf(const std::string &file_name) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  NativeModulePtr m = nullptr;
  ::Module proto;

  std::ifstream fstream(file_name, std::ios::binary);
  if (!fstream.good()) {
    LOG(ERROR)
        << "Failed to open file " << file_name;
    return m;
  }

  if (!proto.ParseFromIstream(&fstream)) {
    LOG(ERROR)
        << "Failed to deserialize protobuf module";
    return m;
  }

  std::unordered_map<VA, NativeFunctionPtr> native_funcs;
  std::list<ExternalCodeRefPtr> extern_funcs;
  std::list<ExternalDataRefPtr> extern_data;
  std::list<DataSection> data_sections;
  std::list<MCSOffsetTablePtr> offset_tables;

  LOG(INFO)
      << "Deserializing externs...";

  for (const auto &external_func : proto.external_funcs()) {
    extern_funcs.push_back(DeserializeExternFunc(external_func));
  }

  LOG(INFO)
      << "Deserializing functions...";

  for (const auto &internal_func : proto.internal_funcs()) {
    auto natf = DeserializeNativeFunc(internal_func, extern_funcs);
    if (!natf) {
      LOG(ERROR)
          << "Unable to deserialize module.";
      return nullptr;
    }
    native_funcs[static_cast<VA>(internal_func.entry_address())] = natf;
  }

  LOG(INFO)
      << "Deserializing data...";
  for (auto &internal_data_elem : proto.internal_data()) {
    DataSection ds;
    DeserializeData(internal_data_elem, ds);
    data_sections.push_back(ds);
  }

  LOG(INFO)
      << "Deserializing external data...";
  for (const auto &exteral_data_elem : proto.external_data()) {
    extern_data.push_back(DeserializeExternData(exteral_data_elem));
  }

  for (const auto &offset_table : proto.offset_tables()) {
    std::vector<std::pair<VA, VA>> v;
    for (auto j = 0; j < offset_table.table_offsets_size(); j++) {
      v.push_back(
          std::make_pair<VA, VA>(offset_table.table_offsets(j),
              offset_table.destinations(j)));
    }

    MCSOffsetTablePtr t(new MCSOffsetTable(v, 0, offset_table.start_addr()));
    offset_tables.push_back(t);
  }

  LOG(INFO)
      << "Creating module...";
  m = NativeModulePtr(
      new NativeModule(proto.module_name(), native_funcs, ArchTriple()));

  //populate the module with externals calls
  LOG(INFO)
      << "Adding external funcs...";
  for (auto &extern_func_call : extern_funcs) {
    m->addExtCall(extern_func_call);
  }

  // Populate the module with externals data
  LOG(INFO)
      << "Adding external data...";
  for (auto &extern_data_ref : extern_data) {
    m->addExtDataRef(extern_data_ref);
  }

  // Populate the module with internal data
  LOG(INFO)
      << "Adding internal data...";
  for (auto &data_section : data_sections) {
    m->addDataSection(data_section);
  }

  LOG(INFO)
      << "Adding Offset Tables...";
  m->addOffsetTables(offset_tables);

  // set entry points for the module
  LOG(INFO)
      << "Adding entry points...";
  for (const auto &entry_symbol : proto.entries()) {
    NativeEntrySymbol native_es(
        entry_symbol.entry_name(),
        entry_symbol.entry_address());

    if (entry_symbol.has_entry_extra()) {
      const auto &ese = entry_symbol.entry_extra();
      auto c = DeserializeCallingConvention(ese.entry_cconv());
      native_es.setExtra(ese.entry_argc(), ese.does_return(), c);
    }
    m->addEntryPoint(native_es);
  }

  LOG(INFO)
      << "Returning module...";
  return m;
}

}  // namespace mcsema

