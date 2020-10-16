/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "CFGWriter.h"

#include <BinaryFunction.h>
#include <Dereference.h>
#include <Function.h>
#include <Immediate.h>
#include <Instruction.h>
#include <InstructionAST.h>
#include <InstructionCategories.h>
#include <Type.h>
#include <entryIDs.h>
#include <gflags/gflags.h>
#include <glog/logging.h>

#include <algorithm>
#include <array>
#include <iterator>
#include <sstream>

#include "Maybe.h"
#include "SectionParser.h"
#include "Util.h"

DECLARE_string(entrypoint);
DECLARE_string(binary);

DECLARE_bool(pie_mode);


using namespace Dyninst;
using namespace mcsema;

mcsema::Module gModule;

namespace {

// Try to eval Dyninst expression
Maybe<Address> TryEval(InstructionAPI::Expression *expr, const Address ip,
                       Address instruction_size = 0) {

  if (auto bin = dynamic_cast<InstructionAPI::BinaryFunction *>(expr)) {
    std::vector<InstructionAPI::InstructionAST::Ptr> args;
    bin->getChildren(args);

    auto left =
        TryEval(dynamic_cast<InstructionAPI::Expression *>(args[0].get()), ip,
                instruction_size);
    auto right =
        TryEval(dynamic_cast<InstructionAPI::Expression *>(args[1].get()), ip,
                instruction_size);

    if (!(left && right)) {
      return {};
    }

    if (bin->isAdd()) {
      return {*left + *right};
    }

    if (bin->isMultiply()) {
      return {*left * *right};
    }
  }

  if (auto imm = dynamic_cast<InstructionAPI::Immediate *>(expr)) {
    return {imm->eval().convert<Address>()};
  }
  if (auto deref = dynamic_cast<InstructionAPI::Dereference *>(expr)) {
    std::vector<InstructionAPI::InstructionAST::Ptr> args;
    deref->getChildren(args);
    return TryEval(dynamic_cast<InstructionAPI::Expression *>(args[0].get()),
                   ip + instruction_size);
  }
  if (auto reg = dynamic_cast<InstructionAPI::RegisterAST *>(expr)) {
    if (reg->format() == "RIP") {
      return {ip};
    }
  }
  return {};
}

// Find call to __libc_start_main@plt and try to recover addresses from it
Address TryRetrieveAddrFromStart(ParseAPI::CodeObject &code_object,
                                 Address start, size_t index) {
  if (!start) {
    LOG(WARNING) << "Binary starts at 0x0";
    return 0;
  }
  for (auto func : code_object.funcs()) {
    if (func->addr() == start) {

      auto entry_block = func->entry();

      using Insn = std::map<Offset, InstructionAPI::Instruction::Ptr>;
      Insn instructions;
      entry_block->getInsns(instructions);
      auto call = std::prev(instructions.end(), 1);

      // Just some sanity check that we are in correct function
      if (call->second->getCategory() != InstructionAPI::c_CallInsn &&
          call->second->getCategory() != InstructionAPI::c_BranchInsn) {
        LOG(WARNING) << "Instruction at 0x" << std::hex << call->first
                     << " is not call nor branching";
        return 0;
      }

      auto mov_inst = std::prev(call, 1 + index);
      auto second_operand = mov_inst->second.get()->getOperand(1);


      // in -pie binaries it will be calculated using lea
      // and it generates unintuitive AST
      auto rip = mov_inst->first;
      if (mov_inst->second->getOperation().getID() == entryID::e_lea) {
        rip += mov_inst->second->size();
      }
      auto offset = TryEval(second_operand.getValue().get(), rip,
                            mov_inst->second->size());

      if (!offset) {
        LOG(WARNING) << "Could not eval basic start addresses!";
        return 0;
      }

      code_object.parse(*offset, true);
      LOG(INFO) << "Retrieving info from _start at index " << index
                << " got addr 0x" << std::hex << *offset << std::dec;
      return *offset;
    }
  }
  LOG(WARNING) << "Was not able to retrieve info from _start at index "
               << index;
  return 0;
}

void RenameFunc(DisassContext &ctx, Dyninst::Address ea,
                const std::string &new_name) {
  auto internal_func = ctx.getInternalFunction(ea);
  if (!internal_func) {
    return;
  }
  internal_func->set_name(new_name);
}

void ResolveOffsetTable(const std::set<Dyninst::Address> &successors,
                        mcsema::Block *cfg_block,
                        const std::vector<OffsetTable> &offset_tables) {

  // For 2 targets offset table should not be generated?
  if (successors.size() < 3) {
    return;
  }

  // Find all xrefs inside this block so they can be matched against offsetTable
  std::set<Dyninst::Address> block_xrefs;
  for (const auto &cfg_inst : cfg_block->instructions()) {
    for (const auto &cfg_xref : cfg_inst.xrefs()) {
      block_xrefs.insert(cfg_xref.ea());
    }
  }

  Maybe<Dyninst::Address> table_ea;
  for (const auto &table : offset_tables) {
    table_ea = table.Match(successors, block_xrefs);
    if (table_ea) {
      break;
    }
  }

  if (table_ea) {
    LOG(INFO) << "Block contains reference to offset table at 0x" << std::hex
              << table_ea.value();
    auto cfg_inst =
        cfg_block->mutable_instructions(cfg_block->instructions_size() - 1);
    if (!cfg_inst->xrefs_size()) {
      AddCodeXref(cfg_inst, CodeReference::OffsetTable, table_ea.value());
    }
  }
}

}  //namespace

CFGWriter::CFGWriter(mcsema::Module &m, SymtabAPI::Symtab &symtab,
                     ParseAPI::CodeObject &code_obj,
                     ExternalFunctionManager &ext_funcs)
    : module(m),
      symtab(symtab),
      code_object(code_obj),
      ext_funcs_m(ext_funcs),
      magic_section(ctx.magic_section),
      ptr_byte_size(symtab.getAddressWidth()) {

  LOG(INFO) << "Binary is stripped: " << symtab.isStripped();
  LOG(INFO) << "Pie_mode: " << FLAGS_pie_mode;

  std::vector<SymtabAPI::Region *> regions;
  symtab.getAllRegions(regions);

  for (auto reg : regions) {
    section_m.AddRegion(reg);
    if (reg->getMemOffset()) {
      ctx.segment_eas.push_back(reg->getMemOffset());
    }
  }

  // We need to get main! Heuristic for stripped binaries is that main is
  // passed to __libc_start_main as last argument from _start, which we can
  // find, because it is entrypoint

  // This does NOT return 0 for shared libraries
  Address entry_point = symtab.getEntryOffset();

  LOG(INFO) << "Entry offset is 0x" << std::hex << entry_point;
  if (entry_point) {
    code_object.parse(entry_point, true);
  }

  Address main_offset = TryRetrieveAddrFromStart(code_object, entry_point, 0);
  Address ctor_offset = TryRetrieveAddrFromStart(code_object, entry_point, 1);
  Address dtor_offset = TryRetrieveAddrFromStart(code_object, entry_point, 2);

  LOG_IF(WARNING, !main_offset) << "Entrypoint was not found!";

  // TODO(lukas): When lifting shared library internal functions that needs
  // to be entrypoints are demangled by ParseAPI, which is really unfortunate
  for (auto func : code_object.funcs()) {
    auto cfg_internal_func = module.add_funcs();

    SymtabAPI::Function *symtab_func;
    if (symtab.findFuncByEntryOffset(symtab_func, func->addr())) {

      // Dyninst for some reason demangle the names
      LOG(INFO) << "Taking mangled name from symtab";
      cfg_internal_func->set_name(*(symtab_func->mangled_names_begin()));
      auto beg = symtab_func->mangled_names_begin();
      while (beg != symtab_func->mangled_names_end()) {
        LOG(INFO) << "\t" << *beg;
        ++beg;
      }
    } else {
      cfg_internal_func->set_name(func->name());
    }
    cfg_internal_func->set_ea(func->addr());
    cfg_internal_func->set_is_entrypoint(false);
    ctx.func_map.insert({func->addr(), cfg_internal_func});
    LOG(INFO) << "Found internal function at 0x" << func->addr()
              << " with name " << cfg_internal_func->name();
  }

  // give entrypoint correct name, most likely main
  if (main_offset) {
    RenameFunc(ctx, main_offset, FLAGS_entrypoint);
  }

  // We need to give libc ctor/dtor names
  if (symtab.isStripped()) {
    if (ctor_offset) {
      RenameFunc(ctx, ctor_offset, "init");
    }
    if (dtor_offset) {
      RenameFunc(ctx, dtor_offset, "fini");
    }
  }

  // Calculate where can magic section start without
  // potentialy overwriting part of the binary
  //TODO(lukas): Move out
  Address highest = 0;
  for (auto reg : regions) {
    highest = std::max(reg->getMemOffset() + reg->getMemSize(), highest);
  }
  highest += 0x420;
  LOG(INFO) << "Magic section starts at 0x" << std::hex << highest;
  magic_section.init(highest, ptr_byte_size);
}

void CFGWriter::WriteFunction(Dyninst::ParseAPI::Function *func,
                              mcsema::Function *cfg_internal_func) {
  ctx.func_map.insert({func->addr(), cfg_internal_func});

  ParseAPI::Block *entryBlock = func->entry();
  cfg_internal_func->set_ea(entryBlock->start());

  cfg_internal_func->set_is_entrypoint(func);

  WriteFunctionBlocks(func, cfg_internal_func);

  cfg_internal_func->set_name(func->name());
  LOG(INFO) << "Added " << func->name() << " into module, found via xref";

  // No need to search for local variables, this is only used when
  // binary is stripped
}

void CFGWriter::Write() {
  WriteExternalFunctions();
  WriteExternalVariables();
  WriteInternalData();

  //WriteGlobalVariables();

  SweepStubs();
  WriteInternalFunctions();

  //Handle new functions found via various xrefs, mostly in stripped binary
  LOG(INFO) << code_xrefs_to_resolve.size() << " code xrefs is unresolved!";
  for (auto &a : code_xrefs_to_resolve) {
    ctx.WriteAndAccount(a.second, true);
    code_object.parse(a.first, true);
  }

  for (auto func : code_object.funcs()) {
    auto code_xref = code_xrefs_to_resolve.find(func->addr());
    if (code_xref != code_xrefs_to_resolve.end() &&
        !ctx.getInternalFunction(func->addr())) {

      auto cfg_internal_func = module.add_funcs();
      WriteFunction(func, cfg_internal_func);
    }
  }

  // In case we discovered some new ones, we need to try until fixpoint
  while (!inst_xrefs_to_resolve.empty()) {
    LOG(WARNING) << inst_xrefs_to_resolve.size()
                 << " inst code xrefs is unresolved!";
    for (auto &a : inst_xrefs_to_resolve) {
      code_object.parse(a.first, false);
    }

    auto old_set = std::move(inst_xrefs_to_resolve);
    for (auto func : code_object.funcs()) {
      if (old_set.find(func->addr()) != old_set.end() &&
          !ctx.getInternalFunction(func->addr())) {

        auto cfg_internal_func = module.add_funcs();
        WriteFunction(func, cfg_internal_func);
      }
    }
  }

  module.set_name(FLAGS_binary);
  ComputeBBAttributes();
}

void CFGWriter::WriteExternalVariables() {
  std::vector<SymtabAPI::Symbol *> symbols;
  symbols = section_m.GetExternalRelocs(
      Dyninst::SymtabAPI::Symbol::SymbolType::ST_OBJECT);

  LOG(INFO) << "Writing " << symbols.size() << " external variables";
  for (const auto &s : symbols) {

    // Is this dynamic?
    if (!s->isInDynSymtab()) {
      continue;
    }

    // Most likely relocation. So as IDA we can also make up some addresses
    if (!s->getOffset() && !s->getSize()) {
      LOG(INFO) << "External var " << s->getMangledName()
                << " had no ea, allocating it in magic section";
      auto external_var =
          magic_section.WriteExternalVariable(module, s->getMangledName());
      ctx.external_vars.insert({external_var->ea(), external_var});
      continue;
    }

    auto external_var = module.add_external_vars();
    ctx.external_vars.insert({s->getOffset(), external_var});
    external_var->set_name(s->getMangledName());
    external_var->set_ea(s->getOffset());

    //TODO(lukas): This is to generate syntactically valid llvm
    //             Other than that probably won't work
    if (s->getSize()) {
      external_var->set_size(s->getSize());
    } else {
      external_var->set_size(ptr_byte_size);
    }

    //TODO(lukas): This needs some checks
    external_var->set_is_weak(
        s->getLinkage() == Dyninst::SymtabAPI::Symbol::SymbolLinkage::SL_WEAK);
    external_var->set_is_thread_local(false);
  }
}

void CFGWriter::WriteGlobalVariables() {
  std::vector<SymtabAPI::Symbol *> vars;
  symtab.getAllSymbolsByType(vars, SymtabAPI::Symbol::ST_OBJECT);
  for (auto &a : vars) {
    if (!a->isInSymtab() || ctx.external_vars.count(a->getOffset())) {
      continue;
    }
    if (a->getRegion() && (a->getRegion()->getRegionName() == ".bss" ||
                           a->getRegion()->getRegionName() == ".rodata")) {
      LOG(INFO) << "Found global variable " << a->getMangledName() << " at "
                << std::hex << a->getOffset() << std::dec;
      auto global_var = module.add_global_vars();
      global_var->set_ea(a->getOffset());
      global_var->set_name(a->getMangledName());
      global_var->set_size(a->getSize());
      ctx.global_vars.insert({a->getOffset(), global_var});
    }
  }
}


// Get information from plt stubs about which external should be called.
// Other frontends do call to external rather than stub, so we should simulate
// this as well
void CFGWriter::SweepStubs() {
  for (ParseAPI::Function *func : code_object.funcs()) {
    if (section_m.IsInRegions({".plt.got"}, func->entry()->start())) {
      auto inst = func->entry()->getInsn(func->addr());

      if (inst->getCategory() == InstructionAPI::c_BranchInsn) {
        auto xref_addr = TryEval(inst->getOperand(0).getValue().get(),
                                 func->addr(), inst->size());
        auto cfg_xref = ctx.data_xrefs.find(*xref_addr);
        if (cfg_xref == ctx.data_xrefs.end()) {
          continue;
        }

        auto cfg_ext_func =
            ctx.external_funcs.find(cfg_xref->second->target_ea());

        if (cfg_ext_func == ctx.external_funcs.end()) {
          continue;
        }
        magic_section.AllocSpace(func->addr(), cfg_ext_func->second->ea());
        ctx.external_funcs.insert({func->addr(), cfg_ext_func->second});
      }
    }
  }
}


void CFGWriter::WriteInternalFunctions() {

  // I don't want this to be in recompiled binary as compiler will
  // add them as well, sub_* is enough
  std::unordered_set<std::string> not_entrypoints = {
      "_dl_relocate_static_pie",
      "register_tm_clones",
      "deregister_tm_clones",
      "__libc_csu_init",
      "frame_dummy",
      "_init",
      "_start",
      "__do_global_dtors_aux",
      "__libc_csu_fini",
      "_fini",
      "__libc_start_main",
      "_GLOBAL__sub_I_main.cpp",
      "__cxx_global_var_init",
      "__cxa_finalize",
  };

  for (ParseAPI::Function *func : code_object.funcs()) {
    if (IsExternal(func->entry()->start())) {
      LOG(INFO) << "Function " << func->name() << " is getting skipped";
      continue;
    }
    // We want to ignore the .got.plt stubs, since they are not needed
    // and cfg file would grow significantly
    else if (section_m.IsInRegions({".got.plt", "plt.got"},
                                   func->entry()->start())) {
      LOG(INFO) << "Function " << func->name()
                << " is getting skipped because it is .got.plt stub";
      continue;
    }

    auto cfg_internal_func = ctx.getInternalFunction(func->addr());

    ParseAPI::Block *entryBlock = func->entry();
    CHECK(entryBlock->start() == static_cast<Address>(cfg_internal_func->ea()))
        << "Start of the block is not equal to function ea";

    cfg_internal_func->set_is_entrypoint(not_entrypoints.find(func->name()) ==
                                         not_entrypoints.end());

    WriteFunctionBlocks(func, cfg_internal_func);
  }
}

// Sometimes Dyninst finds block that ends with instruction in form of
// jmpq absolute_address
// and does not properly set the successor. We check if the target is parsed as
// function already and if yes we add the whole function into the current one
void CFGWriter::WriteFunctionBlocks(ParseAPI::Function *func,
                                    mcsema::Function *cfg_internal_func) {

  std::set<ParseAPI::Block *> written;
  std::set<Address> unknown;
  for (ParseAPI::Block *block : func->blocks()) {
    auto found = WriteBlock(block, func, cfg_internal_func, written);
    unknown.insert(found.begin(), found.end());
  }

  // TODO: More efficient implementation
  for (auto &f : code_object.funcs()) {
    if (unknown.count(f->addr())) {
      for (auto bb : f->blocks()) {

        // This may require calling WriteFunctionBlocks, possible CFG bloat?
        WriteBlock(bb, f, cfg_internal_func, written);
        unknown.erase(f->addr());
      }
    }
  }

  if (!unknown.empty()) {
    std::stringstream targets;
    for (const auto trg : unknown) {
      targets << std::hex << trg << " ";
    }
    LOG(ERROR) << "Unresolved succ of bb was not match to a func: " << std::hex
               << func->addr() << "[ " << targets.str() << " ]";
  }
}

std::set<Address> CFGWriter::WriteBlock(ParseAPI::Block *block,
                                        ParseAPI::Function *func,
                                        mcsema::Function *cfg_internal_func,
                                        std::set<ParseAPI::Block *> &written) {

  if (written.count(block)) {
    return {};
  }

  std::set<Address> unresolved_edges;

  mcsema::Block *cfg_block = cfg_internal_func->add_blocks();
  written.insert(block);
  cfg_block->set_ea(block->start());


  std::map<Offset, InstructionAPI::Instruction::Ptr> instructions;
  block->getInsns(instructions);

  std::set<Address> successors;

  for (auto edge : block->targets()) {

    // TODO(lukas): Exception handling
    // For now ignore catch blocks
    if (edge->type() != Dyninst::ParseAPI::EdgeTypeEnum::CATCH &&
        edge->type() != Dyninst::ParseAPI::EdgeTypeEnum::RET &&
        edge->type() != Dyninst::ParseAPI::EdgeTypeEnum::CALL) {

      auto next = edge->trg()->start();
      auto last_inst = std::prev(instructions.end())->second;
      auto rip = std::prev(instructions.end())->first;

      // Try to compute succ manually, as it can happen that ParseAPI returns -1
      auto manual = TryEval(last_inst->getOperand(0).getValue().get(), rip,
                            last_inst->size());

      // We cannot statically tell anything about this edge
      if (!manual && next == -1) {
        continue;
      }

      auto target = (next == -1) ? *manual : next;

      // There cannot be succs outside of code section
      if (!section_m.IsCode(target)) {
        continue;
      }

      successors.insert(target);
      cfg_block->add_successor_eas(target);

      // We did not find it yet is direct jump -> it is probably beginning of some other
      // function. Target is returned to caller
      if (edge->type() == Dyninst::ParseAPI::EdgeTypeEnum::DIRECT &&
          !func->contains(edge->trg())) {
        unresolved_edges.insert(target);
      }
    }
  }


  // Fact that |successors| must be 3 or more is just a heurestic.
  // It is possible 2 is good enough
  if (successors.size() > 2) {

    bool all = std::all_of(
        successors.cbegin(), successors.cend(),
        [&](auto succ) { return code_xrefs_to_resolve.count(succ); });

    if (all) {
      for (const auto &succ : successors) {
        code_xrefs_to_resolve.erase(succ);
      }
    }
  }

  Address ip = block->start();

  for (auto p = instructions.begin(); p != instructions.end();) {
    InstructionAPI::Instruction *instruction = p->second.get();

    WriteInstruction(instruction, ip, cfg_block, (++p) == instructions.end());
    ip += instruction->size();
  }

  ResolveOffsetTable(successors, cfg_block, offset_tables);
  return unresolved_edges;
}

void CFGWriter::WriteInstruction(InstructionAPI::Instruction *instruction,
                                 Address addr, mcsema::Block *cfg_block,
                                 bool is_last) {

  mcsema::Instruction *cfg_instruction = cfg_block->add_instructions();

  std::string instBytes;
  for (auto offset = 0U; offset < instruction->size(); ++offset) {
    instBytes += (int) instruction->rawByte(offset);
  }

  cfg_instruction->set_ea(addr);

  std::vector<InstructionAPI::Operand> operands;
  instruction->getOperands(operands);

  if (instruction->getCategory() == InstructionAPI::c_CallInsn) {
    HandleCallInstruction(instruction, addr, cfg_instruction, is_last);
  } else {
    HandleNonCallInstruction(instruction, addr, cfg_instruction, cfg_block,
                             is_last);
  }
}


void WriteDisplacement(DisassContext &ctx, SectionManager &section_m,
                       mcsema::Instruction *cfg_instruction, Address &address) {

  // Memory displacement only makes sense if (+ constant) is some xref, otherwise
  // McSema just fills the constant there and there is no need to specify it in cfg
  if (ctx.HandleCodeXref({static_cast<Address>(cfg_instruction->ea()), address,
                          cfg_instruction},
                         section_m)) {

    GetLastXref(cfg_instruction)
        ->set_operand_type(CodeReference::MemoryDisplacementOperand);
  }
}

// For instruction to have MemoryDisplacement it has among other things
// be of type BinaryFunction
Maybe<Address> DisplacementHelper(Dyninst::InstructionAPI::Expression *expr) {

  if (auto top_level = dynamic_cast<InstructionAPI::BinaryFunction *>(expr)) {
    if (!top_level->isAdd()) {
      return 0;
    }

    std::vector<InstructionAPI::InstructionAST::Ptr> inner_operands;
    top_level->getChildren(inner_operands);

    InstructionAPI::BinaryFunction *mid_op = nullptr;
    InstructionAPI::Immediate *mid_imm = nullptr;

    for (auto &inner_op : inner_operands) {

      if (auto middle_level =
              dynamic_cast<InstructionAPI::BinaryFunction *>(inner_op.get())) {
        mid_op = middle_level;
      }

      if (auto middle_level =
              dynamic_cast<InstructionAPI::Immediate *>(inner_op.get())) {
        mid_imm = middle_level;
      }
    }

    if (mid_op && mid_imm) {
      return {mid_imm->eval().convert<Address>()};
    }
  }
  return {};
}

void CFGWriter::CheckDisplacement(Dyninst::InstructionAPI::Expression *expr,
                                  mcsema::Instruction *cfg_instruction) {

  //TODO(lukas): This is possibly incorrect attempt to cull down amount of
  //             "false" xrefs of type MemoryDisplacement
  if (cfg_instruction->xrefs_size()) {
    return;
  }

  if (auto deref = dynamic_cast<InstructionAPI::Dereference *>(expr)) {
    std::vector<InstructionAPI::InstructionAST::Ptr> inner_operands;
    deref->getChildren(inner_operands);

    for (auto &op : inner_operands) {

      if (auto inner_expr =
              dynamic_cast<InstructionAPI::Expression *>(op.get())) {

        if (auto displacement = DisplacementHelper(inner_expr)) {
          WriteDisplacement(ctx, section_m, cfg_instruction, *displacement);
        }
      }
    }
    return;
  }


  if (auto displacement = DisplacementHelper(expr)) {
    WriteDisplacement(ctx, section_m, cfg_instruction, *displacement);
  }
}


//TODO(lukas): This is hacky
void CFGWriter::HandleCallInstruction(InstructionAPI::Instruction *instruction,
                                      Address addr,
                                      mcsema::Instruction *cfg_instruction,
                                      bool is_last) {
  std::vector<InstructionAPI::Operand> operands;
  instruction->getOperands(operands);

  Address size = instruction->size();

  auto target = TryEval(operands[0].getValue().get(), addr, size);
  if (!target) {
    return;
  }

  HandleXref(cfg_instruction, *target);

  // What can happen is that we get xref somewhere in the .text and HandleXref
  // fills it with defaults. We need to check and correct it if needed
  if (section_m.IsCode(*target)) {
    auto xref = cfg_instruction->mutable_xrefs(0);

    //xref->set_target_type(CodeReference::CodeTarget);
    xref->set_operand_type(CodeReference::ControlFlowOperand);

    // It is pointing in .text and not to a function?
    // That's weird, quite possibly we are missing a function!
    if (!ctx.getInternalFunction(*target)) {
      LOG(INFO) << "Unresolved inst_xref " << *target;
      inst_xrefs_to_resolve.insert({*target, {addr, *target, cfg_instruction}});
    }
  }
}

Address CFGWriter::immediateNonCall(InstructionAPI::Immediate *imm,
                                    Address addr,
                                    mcsema::Instruction *cfg_instruction) {

  Address a = imm->eval().convert<Address>();
  if (!ctx.HandleCodeXref({addr, a, cfg_instruction}, section_m, false)) {
    if (section_m.IsCode(a)) {
      AddCodeXref(cfg_instruction, CodeReference::ImmediateOperand, a);

      LOG(INFO) << std::hex
                << "IMM may be working with new function starting at" << a;
      inst_xrefs_to_resolve.insert({a, {}});
      return a;
    }
    return 0;
  }

  GetLastXref(cfg_instruction)
      ->set_operand_type(CodeReference::ImmediateOperand);
  return a;
}

Address CFGWriter::dereferenceNonCall(InstructionAPI::Dereference *deref,
                                      Address addr,
                                      mcsema::Instruction *cfg_instruction) {

  std::vector<InstructionAPI::InstructionAST::Ptr> children;
  deref->getChildren(children);
  auto expr = dynamic_cast<InstructionAPI::Expression *>(children[0].get());

  CHECK(expr) << "Expected expression";

  // TODO(lukas): Possibly may discover new functions?
  auto a = TryEval(expr, addr);
  if (!a) {
    return 0;
  }

  ctx.HandleCodeXref({addr, *a, cfg_instruction}, section_m);
  return *a;
}

//TODO(lukas): Remove
bool CFGWriter::HandleXref(mcsema::Instruction *cfg_instruction, Address addr,
                           bool force) {
  if (ctx.HandleCodeXref({0, addr, cfg_instruction}, section_m, false)) {
    return true;
  }

  if (section_m.IsCode(addr) && !ctx.getInternalFunction(addr)) {
    inst_xrefs_to_resolve.insert(
        {addr,
         {static_cast<Dyninst::Address>(cfg_instruction->ea()), addr,
          cfg_instruction}});
  }

  return ctx.HandleCodeXref({0, addr, cfg_instruction}, section_m, force);
}

void CFGWriter::HandleNonCallInstruction(
    Dyninst::InstructionAPI::Instruction *instruction, Address addr,
    mcsema::Instruction *cfg_instruction, mcsema::Block *cfg_block,
    bool is_last) {

  std::vector<InstructionAPI::Operand> operands;
  instruction->getOperands(operands);

  // RIP already points to the next instruction
  // Except sometimes DynInst thinks it doesn't
  // and construct an AST with + |instruction|
  addr += instruction->size();

  // Sometimes some .text address is stored somewhere in data segment.
  // That can be function pointer, so we need to check if we actually
  // have that function parsed
  Address direct_values[2] = {0, 0};
  auto i = 0U;
  for (auto op : operands) {
    auto expr = op.getValue();

    if (auto imm = dynamic_cast<InstructionAPI::Immediate *>(expr.get())) {
      direct_values[i] =
          (FLAGS_pie_mode) ? 0 : immediateNonCall(imm, addr, cfg_instruction);

    } else if (auto deref =
                   dynamic_cast<InstructionAPI::Dereference *>(expr.get())) {
      direct_values[i] = dereferenceNonCall(deref, addr, cfg_instruction);

    } else if (auto bf =
                   dynamic_cast<InstructionAPI::BinaryFunction *>(expr.get())) {

      auto instruction_id = instruction->getOperation().getID();
      if (instruction_id == entryID::e_lea) {
        if (auto a = TryEval(expr.get(), addr)) {
          HandleXref(cfg_instruction, *a);

          if (section_m.IsCode(*a)) {

            // get last one and change it to code
            GetLastXref(cfg_instruction)
                ->set_operand_type(CodeReference::MemoryOperand);
          }
          direct_values[i] = *a;
        }

      } else if (instruction->getCategory() == InstructionAPI::c_BranchInsn) {

        // This has + |instruction| in AST
        if (auto a = TryEval(expr.get(), addr - instruction->size())) {

          // ea is not really that important
          // in CrossXref<mcsema::Instruction>
          if (ctx.HandleCodeXref({0, *a, cfg_instruction}, section_m)) {
            auto cfg_xref = GetLastXref(cfg_instruction);
            cfg_xref->set_operand_type(CodeReference::ControlFlowOperand);
          }
          direct_values[i] = *a;
        }
      }
    }

    ++i;

    // If we can get value, it is almost certainly not a displacement
    if (!TryEval(expr.get(), addr, instruction->size())) {
      CheckDisplacement(expr.get(), cfg_instruction);
    }
  }

  // We may be storing some address wich is quite possibly entrypoint of
  // something we should treat as function in cfg
  if (direct_values[0] && direct_values[1]) {
    addr -= instruction->size();
    bool is_in_data =
        section_m.IsInRegions({".bss", ".data", ".rodata"}, direct_values[0]);

    if (section_m.IsCode(direct_values[1]) && is_in_data) {

      if (!ctx.getInternalFunction(direct_values[0])) {
        LOG(INFO)
            << "\tAnd it is not parsed yet, storing it to be resolved later!";
        inst_xrefs_to_resolve.insert({direct_values[1], {}});
      }
    }
  }
}

void CFGWriter::WriteExternalFunctions() {
  std::vector<std::string> unknown;
  auto symbols = section_m.GetExternalRelocs(
      Dyninst::SymtabAPI::Symbol::SymbolType::ST_FUNCTION);

  auto known = ext_funcs_m.GetAllUsed(unknown);
  LOG(INFO) << "Found " << known.size() << " known external functions and "
            << unknown.size() << " unknown";

  for (auto &func : known) {
    LOG(INFO) << "External function " << func.symbol_name;
    Address a;
    bool found = false;

    for (auto p : code_object.cs()->linkage()) {
      if (p.second == func.symbol_name) {
        found = true;
        a = p.first;
        break;
      }
    }

    LOG_IF(WARNING, !found)
        << "External function was not found in CodeSource::linkage()";

    func.ea = a;
    auto cfg_external_func = magic_section.WriteExternalFunction(module, func);
    ctx.external_funcs.insert({a, cfg_external_func});
  }
}

void WriteRawData(std::string &data, SymtabAPI::Region *region) {
  auto i = 0U;

  for (; i < region->getDiskSize(); ++i) {
    data += ((const char *) region->getPtrToRawData())[i];
  }

  // Zero padding
  for (; i < region->getMemSize(); ++i) {
    data += '\0';
  }
}

// Writes into section on specified offset
// If offset points beyond section, it is resized to contain it
void WriteAsRaw(std::string &data, uint64_t number, int64_t offset) {

  if (offset < 0) {
    LOG(FATAL) << "Trying to Write raw on negative offset";
  }

  if (static_cast<std::string::size_type>(offset) + 3 >= data.size()) {
    data.resize(offset + 3, '\0');
  }

  for (int i = 0; i < 4; ++i) {
    data[offset + i] = (number >> (i * 8));
  }
}

//TODO(lukas): Relic of old PR, not sure if needed
//             -fPIC & -pie?
void CFGWriter::WriteGOT(SymtabAPI::Region *region,
                         mcsema::Segment *cfg_segment) {
  auto rela_dyn = section_m.GetRegion(".rela.dyn");

  if (!rela_dyn) {
    return;
  }
  const auto &relocations = rela_dyn->getRelocations();

  auto old_data = cfg_segment->mutable_data();
  std::string data{*old_data};
  for (auto reloc : relocations) {
    if (!section_m.IsInRegion(region, reloc.rel_addr())) {
      continue;
    }

    bool found = false;
    LOG(INFO) << "Trying to resolve reloc " << reloc.name();

    for (auto ext_var : magic_section.ext_vars) {
      if (reloc.name() == ext_var->name()) {
        LOG(INFO) << "Writing cfg_xref in got 0x" << std::hex
                  << reloc.rel_addr() << " -> 0x" << ext_var->ea();
        auto cfg_xref = ctx.WriteAndAccount(
            {reloc.rel_addr(), static_cast<Dyninst::Address>(ext_var->ea()),
             cfg_segment, ext_var->name()},
            false);
        found = true;
        ctx.data_xrefs.insert({reloc.rel_addr(), cfg_xref});
        WriteAsRaw(data, ext_var->ea(), reloc.rel_addr() - cfg_segment->ea());
      }
    }
    if (!found && !reloc.name().empty()) {
      LOG(WARNING) << "Giving magic_space to" << reloc.name();

      auto unreal_ea = magic_section.AllocSpace(ptr_byte_size);
      ctx.WriteAndAccount(
          {reloc.rel_addr(), unreal_ea, cfg_segment, reloc.name()}, true);
      WriteAsRaw(data, unreal_ea, reloc.rel_addr() - cfg_segment->ea());

      if (ext_funcs_m.IsExternal(reloc.name())) {
        auto func = ext_funcs_m.GetExternalFunction(reloc.name());
        func.imag_ea = unreal_ea;
        auto cfg_func = func.WriteHelper(module, unreal_ea);
        ctx.external_funcs.insert({unreal_ea, cfg_func});
      }
    }
  }

  cfg_segment->set_data(data);
}

void CFGWriter::WriteRelocations(SymtabAPI::Region *region,
                                 mcsema::Segment *segment) {

  auto rela_dyn = section_m.GetRegion(".rela.plt");
  if (!rela_dyn) {
    return;
  }
  const auto &relocations = rela_dyn->getRelocations();
  auto data = segment->mutable_data();

  for (auto reloc : relocations) {
    LOG(INFO) << "Trying to resolve reloc " << reloc.name();
    for (auto ext_func : magic_section.ext_funcs) {
      if (reloc.name() == ext_func->name()) {
        LOG(INFO) << "Writing xref in got 0x" << std::hex << reloc.rel_addr()
                  << " -> 0x" << ext_func->ea();
        ctx.WriteAndAccount({reloc.rel_addr(),
                             static_cast<Dyninst::Address>(ext_func->ea()),
                             segment, ext_func->name()});
        WriteAsRaw(*data, ext_func->ea(), reloc.rel_addr() - segment->ea());
      }
    }
  }
}

void WriteBssXrefs(DisassContext &ctx, SectionManager &section_m,
                   SymtabAPI::Region *region, mcsema::Segment *segment) {
  for (auto &external : ctx.external_vars) {
    if (section_m.IsInRegion(region, external.first)) {
      ctx.WriteAndAccount(
          {external.first, external.first, segment, external.second->name()},
          false /*, external.second->size()*/);
    }
  }
}

// Write content of sections, try to parse for xrefs and vars
// .rodata, .data have special treatment, since there can be string
// variables and such
void CFGWriter::WriteInternalData() {
  auto dataRegions = section_m.GetAllRegions();
  SectionParser section_parser(&ctx, section_m);

  for (auto region : dataRegions) {

    // IDA does not include some of these, so neither should we
    const static std::set<std::string> no_parse = {
        ".dynamic",
        ".dynstr",
        ".dynsym",
    };

    if (no_parse.find(region->getRegionName()) != no_parse.end()) {
      continue;
    }

    // Sanity check
    LOG(INFO) << "Writing region " << region->getRegionName();
    if (region->getMemSize() <= 0) {
      continue;
    }

    if (region->getRegionName() == ".fini_array") {
      continue;
    }
    auto cfg_internal_data = module.add_segments();
    section_m.SetCFG(region, cfg_internal_data);

    std::string data;
    WriteRawData(data, region);

    // .init & .fini should be together
    if (region->getRegionName() == ".init_array") {
      SymtabAPI::Region *fini;
      symtab.findRegion(fini, ".fini_array");
      WriteRawData(data, fini);
      WriteDataVariables(fini, cfg_internal_data, section_parser);

      section_parser.XrefsInSegment(fini, cfg_internal_data);
    }

    cfg_internal_data->set_ea(region->getMemOffset());
    cfg_internal_data->set_data(data);
    cfg_internal_data->set_read_only(region->getRegionPermissions() ==
                                     SymtabAPI::Region::RP_R);
    cfg_internal_data->set_is_external(false);
    cfg_internal_data->set_name(region->getRegionName());
    cfg_internal_data->set_is_exported(false); /* TODO: As for now, ignored */
    cfg_internal_data->set_is_thread_local(
        false); /* TODO: As for now, ignored */

    const static std::set<std::string> dont_parse = {
        ".eh_frame",
        ".rela.dyn",
        ".rela.plt",
        ".dynamic",
        ".dynstr",
        ".dynsym",
        ".got",
        ".got.plt",
        ".plt",
        ".plt.got",
        ".gnu.hash",
        ".gnu.version",
        ".gcc_except_table",
        ".jcr",
    };

    if (dont_parse.find(region->getRegionName()) == dont_parse.end()) {
      WriteDataVariables(region, cfg_internal_data, section_parser);

      section_parser.XrefsInSegment(region, cfg_internal_data);
    }

    // IDA output of .bss produced some "self xrefs"
    if (region->getRegionName() == ".bss") {
      WriteBssXrefs(ctx, section_m, region, cfg_internal_data);
    }

    // Apply relocations of external functions
    if (region->getRegionName() == ".got.plt") {
      WriteRelocations(region, cfg_internal_data);
    }

    // Apply relocations of external variables if needed
    if (region->getRegionName() == ".got") {
      WriteGOT(region, cfg_internal_data);
    }
  }
  code_xrefs_to_resolve = section_parser.ResolveCrossXrefs();
  offset_tables = section_parser.GetOffsetTables();
}

void CFGWriter::WriteDataVariables(Dyninst::SymtabAPI::Region *region,
                                   mcsema::Segment *segment,
                                   SectionParser &section_parser) {
  std::vector<SymtabAPI::Symbol *> vars;
  symtab.getAllSymbolsByType(vars, SymtabAPI::Symbol::ST_OBJECT);

  for (auto &a : vars) {
    if ((a->getRegion() && a->getRegion() == region) ||
        (a->getOffset() == region->getMemOffset())) {

      if (ctx.external_vars.find(a->getOffset()) != ctx.external_vars.end() ||
          ctx.segment_vars.count(a->getOffset())) {
        continue;
      }

      // TODO(lukas): Var recovery related
      /*
      auto var = segment->add_vars();
      var->set_ea(a->getOffset());
      var->set_name(a->getMangledName());
      LOG(INFO) << "Added var 0x" << std::hex << a->getOffset();
      ctx.segment_vars.insert({a->getOffset(), var});
      */
    }
  }
  if (region->getRegionName() == ".rodata" ||
      region->getRegionName() == ".data" ||
      region->getRegionName() == ".data.rel.ro") {
    LOG(INFO) << "Speculative parse of " << region->getRegionName();
    section_parser.ParseVariables(region, segment);
  }
}


bool CFGWriter::IsExternal(Address addr) const {
  return ctx.external_vars.find(addr) != ctx.external_vars.end() ||
         ctx.external_funcs.find(addr) != ctx.external_funcs.end();
}

// Set `is_referenced_by_data`. This is independent from the
// actual xref resolution and is done as last step.
// TODO(lukas): We may need mark offset tables entries as well.
void CFGWriter::ComputeBBAttributes() {
  std::unordered_map<uint64_t, mcsema::Block *> bbs;
  for (auto &cfg_fn : *module.mutable_funcs()) {
    for (auto &cfg_bb : *cfg_fn.mutable_blocks()) {
      bbs.emplace(cfg_bb.ea(), &cfg_bb);
      cfg_bb.set_is_referenced_by_data(false);
    }
  }

  for (auto &[ea, cfg_dref] : ctx.data_xrefs) {
    auto it = bbs.find(cfg_dref->target_ea());
    if (it == bbs.end())
      continue;
    it->second->set_is_referenced_by_data(true);
  }
}
