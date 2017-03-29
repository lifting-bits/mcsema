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

size_t NativeInst::get_len(void) const {
  return this->len;
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

NativeInst::NativeInst(VA v, const std::string &bytes_)
    : tgtIfTrue(0),
      tgtIfFalse(0),
      loc(v),
      bytes(bytes_),

      external_code_ref(nullptr),
      code_addr(~0ULL),

      external_mem_data_ref(nullptr),
      external_mem_code_ref(nullptr),
      external_disp_data_ref(nullptr),
      external_disp_code_ref(nullptr),
      external_imm_data_ref(nullptr),
      external_imm_code_ref(nullptr),

      mem_ref_data_addr(~0ULL),
      mem_ref_code_addr(~0ULL),

      disp_ref_data_addr(~0ULL),
      disp_ref_code_addr(~0ULL),

      imm_ref_data_addr(~0ULL),
      imm_ref_code_addr(~0ULL),

      jumpTable(nullptr),
      jump_table(false),
      jumpIndexTable(nullptr),
      jump_index_table(false),
      len(bytes.size()),
      is_terminator(false),
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
  this->follows.insert(f);
}

std::set<VA> &NativeBlock::get_follows(void) {
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
  if (funcSymName.empty()) {
    std::stringstream ss;
    ss << "sub_" << std::hex << this->funcEntryVA;
    return ss.str();
  } else {
    return funcSymName;
  }
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

  for (const auto &ref : inst.refs()) {
    ExternalDataRefPtr ext_data_ref = nullptr;
    VA data_addr = ~0ULL;

    ExternalCodeRefPtr ext_code_ref = nullptr;
    VA code_addr = ~0ULL;

    if (ref.target_type() == Reference_TargetType_CodeTarget) {
      code_addr = ref.address();
    } else {
      data_addr = ref.address();
    }

    if (ref.location() == Reference_Location_External) {
      const auto &name = ref.name();
      CHECK(!name.empty())
          << "External code reference from instruction " << std::hex
          << inst.inst_addr() << " doesn't have a name.";

      if (ref.target_type() == Reference_TargetType_CodeTarget) {
        ext_code_ref = getExternal(name, extcode);
        CHECK(ext_code_ref != nullptr)
            << "Could not find external code " << name << " at address "
            << std::hex << code_addr;

      } else {
        ext_data_ref = new ExternalDataRef(name);
      }
    }

    switch (ref.operand_type()) {
      case Reference_OperandType_ImmediateOperand:
        ip->imm_ref_code_addr = code_addr;
        ip->imm_ref_data_addr = data_addr;
        ip->external_imm_code_ref = ext_code_ref;
        ip->external_imm_data_ref = ext_data_ref;
        break;
      case Reference_OperandType_MemoryOperand:
        ip->mem_ref_code_addr = code_addr;
        ip->mem_ref_data_addr = data_addr;
        ip->external_mem_code_ref = ext_code_ref;
        ip->external_mem_data_ref = ext_data_ref;
        break;
      case Reference_OperandType_MemoryDisplacementOperand:
        ip->disp_ref_code_addr = code_addr;
        ip->disp_ref_data_addr = data_addr;
        ip->external_disp_code_ref = ext_code_ref;
        ip->external_disp_data_ref = ext_data_ref;
        break;
      case Reference_OperandType_ControlFlowOperand:
        ip->external_code_ref = ext_code_ref;
        ip->code_addr = code_addr;
        break;
    }
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

