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

#include <iostream>
#include <fstream>
#include <sstream>
#include <utility>

#include "CFG.pb.h"  // Auto-generated.

#include "mcsema/Arch/Arch.h"
#include "mcsema/CFG/CFG.h"

#include "mcsema/cfgToLLVM/TransExcn.h"

#include "mcsema/cfgToLLVM/Externals.h"
#include "mcsema/cfgToLLVM/JumpTables.h"

bool NativeInst::terminator(void) const {
  return this->is_terminator;
}

void NativeInst::set_terminator(void) {
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

  std::cerr << __FUNCTION__ << ": Adding  ref: " << ops << ", to: " << std::hex
            << ref << ", ro: " << ro << ", rt: " << rts << std::endl;
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
  } else if (op == IMMRef) {
    return this->imm_ref_type;
  } else {
    //TODO throw exception?
    //return -1;
    return this->mem_ref_type;
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

llvm::MCInst &NativeInst::get_inst(void) {
  return this->decoded_inst;
}

void NativeInst::set_inst(const llvm::MCInst &i) {
  this->decoded_inst = i;
}

VA NativeInst::get_loc(void) const {
  return this->loc;
}

void NativeInst::set_tr(VA a) {
  this->tgtIfTrue = a;
}

void NativeInst::set_fa(VA a) {
  this->tgtIfFalse = a;
}

VA NativeInst::get_tr(void) const {
  return this->tgtIfTrue;
}

VA NativeInst::get_fa(void) const {
  return this->tgtIfFalse;
}

uint8_t NativeInst::get_len(void) const {
  return this->len;
}

void NativeInst::set_call_tgt(VA addr) {
  this->targets.push_back(addr);
  return;
}

bool NativeInst::has_call_tgt(void) const {
  return !this->targets.empty();
}

VA NativeInst::get_call_tgt(int index) const {
  return this->targets.at(index);
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

bool NativeInst::has_rip_relative(void) const {
  return this->hasRIP;
}

VA NativeInst::get_rip_relative(void) const {
  return this->rip_target;
}

void NativeInst::set_rip_relative(unsigned i) {
  const llvm::MCOperand &base = decoded_inst.getOperand(i + 0);
  const llvm::MCOperand &scale = decoded_inst.getOperand(i + 1);
  const llvm::MCOperand &index = decoded_inst.getOperand(i + 2);
  const llvm::MCOperand &disp = decoded_inst.getOperand(i + 3);

  rip_target = loc + len + disp.getImm();
  //const
  this->hasRIP = true;
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

unsigned int NativeInst::get_opcode(void) const {
  return this->decoded_inst.getOpcode();
}

ExternalCodeRefPtr NativeInst::get_ext_call_target(void) const {
  return this->extCallTgt;
}
ExternalDataRefPtr NativeInst::get_ext_data_ref(void) const {
  return this->extDataRef;
}

NativeInst::NativeInst(VA v, uint8_t l, const llvm::MCInst &inst, Prefix k)
    : tgtIfTrue(0),
      tgtIfFalse(0),
      loc(v),
      decoded_inst(inst),
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
      offset_table( -1) {}

DataSectionEntry::DataSectionEntry(uint64_t base, const std::vector<uint8_t> &b)
    : base(base),
      bytes(b),
      is_symbol(false) {}

DataSectionEntry::DataSectionEntry(uint64_t base, const std::string &sname)
    : base(base),
      sym_name(sname),
      is_symbol(true) {

  this->bytes.push_back(0x0);
  this->bytes.push_back(0x0);
  this->bytes.push_back(0x0);
  this->bytes.push_back(0x0);
}

DataSectionEntry::DataSectionEntry(uint64_t base, const std::string &sname,
                                   uint64_t symbol_size)
    : base(base),
      bytes(symbol_size),
      sym_name(sname),
      is_symbol(true) {}

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
  TASSERT(block_it != blocks.end(), "Block not found");
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
  TASSERT( !this->blocks.count(blockBase), "Added duplicate block!");
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

//add an external reference
void NativeModule::addExtCall(ExternalCodeRefPtr p) {
  this->external_code_refs.push_back(p);
}

const std::list<ExternalCodeRefPtr> &NativeModule::getExtCalls(void) const {
  return this->external_code_refs;
}

//external data ref
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
    std::cerr
        << "Adding offset table at " << std::hex
        << table->getStartAddr() << std::endl;
    this->offset_tables.insert( {table->getStartAddr(), table});
  }
}

NativeInst::CFGRefType deserRefType(::Instruction::RefType k) {
  switch (k) {
    case ::Instruction::CodeRef:
      return NativeInst::CFGCodeRef;
    case ::Instruction::DataRef:
      return NativeInst::CFGDataRef;
    default:
      throw TErr(__LINE__, __FILE__, "Unsupported Ref Type");
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

static NativeInst::Prefix GetPrefix(const llvm::MCInst &inst) {
  switch (inst.getOpcode()) {
    case llvm::X86::REP_MOVSB_32:
    case llvm::X86::REP_MOVSB_64:
    case llvm::X86::REP_MOVSW_32:
    case llvm::X86::REP_MOVSW_64:
    case llvm::X86::REP_MOVSD_32:
    case llvm::X86::REP_MOVSD_64:
    case llvm::X86::REP_MOVSQ_64:
    case llvm::X86::REP_LODSB_32:
    case llvm::X86::REP_LODSB_64:
    case llvm::X86::REP_LODSW_32:
    case llvm::X86::REP_LODSW_64:
    case llvm::X86::REP_LODSD_32:
    case llvm::X86::REP_LODSD_64:
    case llvm::X86::REP_LODSQ_64:
    case llvm::X86::REP_STOSB_32:
    case llvm::X86::REP_STOSB_64:
    case llvm::X86::REP_STOSW_32:
    case llvm::X86::REP_STOSW_64:
    case llvm::X86::REP_STOSD_32:
    case llvm::X86::REP_STOSD_64:
    case llvm::X86::REP_STOSQ_64:
      return NativeInst::RepPrefix;

    case llvm::X86::REPE_CMPSB_32:
    case llvm::X86::REPE_CMPSB_64:
    case llvm::X86::REPE_CMPSW_32:
    case llvm::X86::REPE_CMPSW_64:
    case llvm::X86::REPE_CMPSD_32:
    case llvm::X86::REPE_CMPSD_64:
    case llvm::X86::REPE_CMPSQ_64:
      return NativeInst::RepPrefix;

    case llvm::X86::REPNE_CMPSB_32:
    case llvm::X86::REPNE_CMPSB_64:
    case llvm::X86::REPNE_CMPSW_32:
    case llvm::X86::REPNE_CMPSW_64:
    case llvm::X86::REPNE_CMPSD_32:
    case llvm::X86::REPNE_CMPSD_64:
    case llvm::X86::REPNE_CMPSQ_64:
      return NativeInst::RepNePrefix;

    case llvm::X86::REPE_SCASB_32:
    case llvm::X86::REPE_SCASB_64:
    case llvm::X86::REPE_SCASW_32:
    case llvm::X86::REPE_SCASW_64:
    case llvm::X86::REPE_SCASD_32:
    case llvm::X86::REPE_SCASD_64:
    case llvm::X86::REPE_SCASQ_64:
      return NativeInst::RepPrefix;

    case llvm::X86::REPNE_SCASB_32:
    case llvm::X86::REPNE_SCASB_64:
    case llvm::X86::REPNE_SCASW_32:
    case llvm::X86::REPNE_SCASW_64:
    case llvm::X86::REPNE_SCASD_32:
    case llvm::X86::REPNE_SCASD_64:
    case llvm::X86::REPNE_SCASQ_64:
      return NativeInst::RepNePrefix;
  }

  for (const auto &op : inst) {
    if (op.isReg()) {
      if (op.getReg() == llvm::X86::GS) {
        return NativeInst::GSPrefix;
      } else if (op.getReg() == llvm::X86::FS) {
        return NativeInst::FSPrefix;
      }
    }
  }

  return NativeInst::NoPrefix;
}

static NativeInstPtr DecodeInst(
    uintptr_t addr, const std::vector<uint8_t> &bytes) {

  VA nextVA = addr;
  // Get the maximum number of bytes for decoding.
  uint8_t decodable_bytes[kMaxNumInstrBytes] = {};
  std::copy(bytes.begin(), bytes.end(), decodable_bytes);
  auto max_size = bytes.size();

  // Try to decode the instruction.
  llvm::MCInst mcInst;
  auto num_decoded_bytes = ArchDecodeInstruction(
      decodable_bytes, decodable_bytes + max_size, addr, mcInst);

  if (!num_decoded_bytes) {
    std::cerr
        << "Failed to decode instruction at address "
        << std::hex << addr << std::endl;
    return nullptr;
  }

  NativeInstPtr inst = new NativeInst(
      addr, num_decoded_bytes, mcInst, GetPrefix(mcInst));

  // Mark some operands as being RIP-relative.
  for (auto i = 0U; i < mcInst.getNumOperands(); ++i) {
    const auto &Op = mcInst.getOperand(i);
    if (Op.isReg() && Op.getReg() == llvm::X86::RIP) {
      inst->set_rip_relative(i);
    }
  }

  llvm::MCOperand oper;

  //ask if this is a jmp, and figure out what the true / false follows are
  switch (mcInst.getOpcode()) {
    case llvm::X86::JMP32m:
    case llvm::X86::JMP32r:
    case llvm::X86::JMP64m:
    case llvm::X86::JMP64r:
      inst->set_terminator();
      break;
    case llvm::X86::RETL:
    case llvm::X86::RETIL:
    case llvm::X86::RETIQ:
    case llvm::X86::RETIW:
    case llvm::X86::RETQ:
      inst->set_terminator();
      break;
    case llvm::X86::JMP_4:
    case llvm::X86::JMP_1:
      oper = mcInst.getOperand(0);
      if (oper.isImm()) {
        nextVA += oper.getImm() + num_decoded_bytes;
        inst->set_tr(nextVA);
      } else {
        std::cerr << "Unhandled indirect branch at 0x" << std::hex << addr;
        return nullptr;
      }
      break;
    case llvm::X86::LOOP:
    case llvm::X86::LOOPE:
    case llvm::X86::LOOPNE:
    case llvm::X86::JO_4:
    case llvm::X86::JO_1:
    case llvm::X86::JNO_4:
    case llvm::X86::JNO_1:
    case llvm::X86::JB_4:
    case llvm::X86::JB_1:
    case llvm::X86::JAE_4:
    case llvm::X86::JAE_1:
    case llvm::X86::JE_4:
    case llvm::X86::JE_1:
    case llvm::X86::JNE_4:
    case llvm::X86::JNE_1:
    case llvm::X86::JBE_4:
    case llvm::X86::JBE_1:
    case llvm::X86::JA_4:
    case llvm::X86::JA_1:
    case llvm::X86::JS_4:
    case llvm::X86::JS_1:
    case llvm::X86::JNS_4:
    case llvm::X86::JNS_1:
    case llvm::X86::JP_4:
    case llvm::X86::JP_1:
    case llvm::X86::JNP_4:
    case llvm::X86::JNP_1:
    case llvm::X86::JL_4:
    case llvm::X86::JL_1:
    case llvm::X86::JGE_4:
    case llvm::X86::JGE_1:
    case llvm::X86::JLE_4:
    case llvm::X86::JLE_1:
    case llvm::X86::JG_4:
    case llvm::X86::JG_1:
    case llvm::X86::JCXZ:
    case llvm::X86::JECXZ:
    case llvm::X86::JRCXZ:
      oper = mcInst.getOperand(0);
      inst->set_tr(addr + oper.getImm() + num_decoded_bytes);
      inst->set_fa(addr + num_decoded_bytes);
      break;
  }

  return inst;
}

static NativeInstPtr DeserializeInst(
    const ::Instruction &inst,
    const std::list<ExternalCodeRefPtr> &extcode) {
  VA addr = inst.inst_addr();
  auto tr_tgt = static_cast<VA>(inst.true_target());
  auto fa_tgt = static_cast<VA>(inst.false_target());
  const auto &bytes_str = inst.inst_bytes();
  std::vector<uint8_t> bytes(bytes_str.begin(), bytes_str.end());

  //produce an MCInst from the instruction buffer using the ByteDecoder
  NativeInstPtr ip = DecodeInst(addr, bytes);
  if (!ip) {
    std::cerr
        << "Unable to deserialize inst at " << std::hex << addr << std::endl;
    return nullptr;
  }

  if (tr_tgt > 0) {
    ip->set_tr(tr_tgt);
  }

  if (fa_tgt > 0) {
    ip->set_fa(fa_tgt);
  }

  if (inst.has_ext_call_name()) {
    ExternalCodeRefPtr p = getExternal(inst.ext_call_name(), extcode);
    if (p == nullptr) {
      throw TErr(__LINE__, __FILE__,
                 "Could not find external: " + inst.ext_call_name());
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
    NativeInst::CFGRefType rt;

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
    NativeInst::CFGRefType rt;

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

    VA data_offset = (VA) ( -1);
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

static NativeBlockPtr deserializeBlock(
    const ::Block &block,
    const std::list<ExternalCodeRefPtr> &extcode) {

  auto block_va = static_cast<VA>(block.base_address());
  NativeBlockPtr natB = NativeBlockPtr(new NativeBlock(block_va));

  for (auto &inst : block.insts()) {
    auto native_inst = DeserializeInst(inst, extcode);
    if (!native_inst) {
      std::cerr
          << "Unable to deserialize block at " << std::hex
          << block_va << std::endl;
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

  //read all the blocks from this function
  for (auto &block : func.blocks()) {
    auto native_block = deserializeBlock(block, extcode);
    if (!native_block) {
      std::cerr
          << "Unable to deserialize function at " << std::hex
          << func.entry_address() << std::endl;
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
      break;

    case ::ExternalFunction::CalleeCleanup:
      return ExternalCodeRef::CalleeCleanup;
      break;

    case ::ExternalFunction::FastCall:
      return ExternalCodeRef::FastCall;
      break;

    case ::ExternalFunction::McsemaCall:
      return ExternalCodeRef::McsemaCall;
      break;

    default:
      throw TErr(__LINE__, __FILE__, "Unsupported CC");
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
  std::cerr
      << "Deserializing symbol at: " << std::hex << ds.base_address() << ", "
      << ds.symbol_name() << ", " << ds.symbol_size() << std::endl;

  return DataSectionEntry(ds.base_address(), ds.symbol_name(), ds.symbol_size());
}

static DataSectionEntry makeDSEBlob(const std::vector<uint8_t> &bytes,
                                    uint64_t start,  // offset in bytes vector
    uint64_t end,  // offset in bytes vector
    uint64_t base_va)  // virtual address these bytes are based at
    {
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

  //DataSectionEntry  dse(d.base_address(), bytes);
  std::vector<uint8_t>::iterator bytepos = bytes.begin();

  // assumes symbols are in-order
  for (int i = 0; i < d.symbols_size(); i++) {
    DataSectionEntry dse_sym = DeserializeDataSymbol(d.symbols(i));
    auto dse_base = dse_sym.getBase();

    std::cerr
        << "cur_pos: " << std::hex << cur_pos << std::endl
        << "dse_base: " << std::hex << dse_base << std::endl;

    // symbol next to blob
    if (dse_base > cur_pos) {
      ds.addEntry(
          makeDSEBlob(bytes, cur_pos - base_address, dse_base - base_address,
                      cur_pos));
      ds.addEntry(dse_sym);

      cur_pos = dse_base + dse_sym.getSize();
      std::cerr
          << "new_cur_pos: " << std::hex << cur_pos << std::endl;

      // symbols next to each other
    } else if (dse_base == cur_pos) {
      ds.addEntry(dse_sym);
      cur_pos = dse_base + dse_sym.getSize();
      std::cerr
          << "new_cur_pos2: " << std::hex << cur_pos << std::endl;

    } else {
      std::cerr
          << __FILE__ << ":" << __LINE__ << std::endl
          << "Deserialized an out-of-order symbol!" << std::endl;
      throw TErr(__LINE__, __FILE__, "Deserialized an out-of-order symbol!");
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

  NativeModulePtr m;
  ::Module proto;

  std::ifstream fstream(file_name, std::ios::binary);
  if (!fstream.good()) {
    std::cerr << "Failed to open file " << file_name << std::endl;
    return m;
  }

  //read the protobuf object in
  if (!proto.ParseFromIstream(&fstream)) {
    std::cerr << "Failed to deserialize protobuf module" << std::endl;
    return m;
  }

  std::unordered_map<VA, NativeFunctionPtr> native_funcs;
  std::list<ExternalCodeRefPtr> extern_funcs;
  std::list<ExternalDataRefPtr> extern_data;
  std::list<DataSection> data_sections;
  std::list<MCSOffsetTablePtr> offset_tables;

  std::cerr << "Deserializing externs..." << std::endl;
  for (const auto &external_func : proto.external_funcs()) {
    extern_funcs.push_back(DeserializeExternFunc(external_func));
  }

  std::cerr << "Deserializing functions..." << std::endl;
  for (const auto &internal_func : proto.internal_funcs()) {
    auto natf = DeserializeNativeFunc(internal_func, extern_funcs);
    if (!natf) {
      std::cerr << "Unable to deserialize module." << std::endl;
      return nullptr;
    }
    native_funcs[static_cast<VA>(internal_func.entry_address())] = natf;
  }

  std::cerr << "Deserializing data..." << std::endl;
  for (auto &internal_data_elem : proto.internal_data()) {
    DataSection ds;
    DeserializeData(internal_data_elem, ds);
    data_sections.push_back(ds);
  }

  std::cerr << "Deserializing external data..." << std::endl;
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

  std::cerr << "Creating module..." << std::endl;
  m = NativeModulePtr(
      new NativeModule(proto.module_name(), native_funcs, ArchTriple()));

  //populate the module with externals calls
  std::cerr << "Adding external funcs..." << std::endl;
  for (auto &extern_func_call : extern_funcs) {
    m->addExtCall(extern_func_call);
  }

  //populate the module with externals data
  std::cerr << "Adding external data..." << std::endl;
  for (auto &extern_data_ref : extern_data) {
    m->addExtDataRef(extern_data_ref);
  }

  //populate the module with internal data
  std::cerr << "Adding internal data..." << std::endl;
  for (auto &data_section : data_sections) {
    m->addDataSection(data_section);
  }

  std::cerr << "Adding Offset Tables..." << std::endl;
  m->addOffsetTables(offset_tables);

  // set entry points for the module
  std::cerr << "Adding entry points..." << std::endl;
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

  std::cerr << "Returning modue..." << std::endl;
  return m;
}
