/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "CFGWriter.h"

#include "Util.h"
#include "SectionParser.h"

#include <Dereference.h>
#include <BinaryFunction.h>
#include <Immediate.h>
#include <Function.h>
#include <Instruction.h>
#include <InstructionAST.h>
#include <InstructionCategories.h>
#include <Type.h>
#include <entryIDs.h>

#include <sstream>
#include <array>
#include <iterator>

#include <glog/logging.h>
#include <gflags/gflags.h>

DECLARE_string(entrypoint);
DECLARE_string(binary);

DECLARE_bool(pie_mode);


using namespace Dyninst;
using namespace mcsema;

mcsema::Module gModule;

namespace {

// Try to eval Dyninst expression
bool TryEval(InstructionAPI::Expression *expr,
                        const Address ip,
                        Address &result,
                        Address instruction_size=0) {

  if (auto bin = dynamic_cast<InstructionAPI::BinaryFunction *>(expr)) {
    std::vector<InstructionAPI::InstructionAST::Ptr> args;
    bin->getChildren(args);

    Address left, right;

    auto first = TryEval(
        dynamic_cast<InstructionAPI::Expression *>(args[0].get()),
        ip, left, instruction_size);
    auto second = TryEval(
        dynamic_cast<InstructionAPI::Expression *>(args[1].get()),
        ip, right, instruction_size);
    if (first && second) {
      if (bin->isAdd()) {
        result = left + right;
        return true;
      } else if (bin->isMultiply()) {
        result = left * right;
        return true;
      }

      return false;
    }
  }  else if (auto imm = dynamic_cast<InstructionAPI::Immediate *>(expr)) {
    result = imm->eval().convert<Address>();
    return true;
  } else if (auto deref = dynamic_cast<InstructionAPI::Dereference *>(expr)) {
    std::vector<InstructionAPI::InstructionAST::Ptr> args;
    deref->getChildren(args);
    return TryEval(dynamic_cast<InstructionAPI::Expression *>(args[0].get()),
                   ip + instruction_size,
                   result);
  } else if (auto reg = dynamic_cast<InstructionAPI::RegisterAST *>(expr)) {
    if (reg->format() == "RIP") {
      result = ip;
      return true;
    }
  }
  return false;
}

// Find call to __libc_start_main@plt and try to recover addresses from it
Address TryRetrieveAddrFromStart(ParseAPI::CodeObject &code_object,
                                 Address start,
                                 size_t index) {
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

      Address offset = 0;

      // in -pie binaries it will be calculated using lea
      // and it generates unintuitive AST
      auto rip = mov_inst->first;
      if (mov_inst->second->getOperation().getID() == entryID::e_lea) {
        rip += mov_inst->second->size();
      }
      if (!TryEval(second_operand.getValue().get(), rip, offset,
                   mov_inst->second->size())) {
        LOG(WARNING) << "Could not eval basic start addresses!";
        return 0;
      }
      code_object.parse(offset, true);
      LOG(INFO) << "Retrieving info from _start at index " << index
                << " got addr 0x" << std::hex << offset << std::dec;
      return offset;
    }
  }
  LOG(WARNING) << "Was not able to retrieve info from _start at index "
               << index;
  return 0;
}

// Modifies gDisassContext
void RenameFunc(Dyninst::Address ea, const std::string& new_name) {
  LOG(INFO) << "Renaming 0x:" << std::hex << ea << " to " << new_name;
  auto internal_func = gDisassContext->getInternalFunction(ea);
  if (!internal_func) {
    return;
  }
  internal_func->set_name(new_name);
}

void ResolveOffsetTable(const std::set<Dyninst::Address> &successors,
                        mcsema::Block *cfg_block,
                        const std::vector<OffsetTable> offset_tables) {
  // For 2 targets offset table should not be generated?
  if (successors.size() < 3) {
    return;
  }

  LOG(INFO) << "Checking for offset table xref in " << offset_tables.size();

  // Find all xrefs inside this block so they can be matched against offsetTable
  std::set<Dyninst::Address> block_xrefs;
  for (const auto &cfg_inst : cfg_block->instructions()) {
    for (const auto &cfg_xref : cfg_inst.xrefs()) {
      block_xrefs.insert(cfg_xref.ea());
    }
  }

  std::experimental::optional<Dyninst::Address> table_ea;
  for (const auto &table : offset_tables) {
    table_ea = table.Match(successors, block_xrefs);
    if (table_ea) {
      break;
    }
  }

  if (table_ea) {
    LOG(INFO) << "Block contains reference to offset table at 0x"
              << std::hex << table_ea.value();
    auto cfg_inst = cfg_block->mutable_instructions(
        cfg_block->instructions_size() - 1);
    if (!cfg_inst->xrefs_size()) {
      AddCodeXref(cfg_inst, CodeReference::DataTarget, CodeReference::OffsetTable,
                  CodeReference::Internal, table_ea.value());
    }
  }

}

} //namespace

CFGWriter::CFGWriter(mcsema::Module &m,
                     SymtabAPI::Symtab &symtab,
                     ParseAPI::SymtabCodeSource &symCodeSrc,
                     ParseAPI::CodeObject &codeObj)
    : module(m),
      symtab(symtab),
      code_object(codeObj),
      code_source(symCodeSrc),
      magic_section(gDisassContext->magic_section),
      ptr_byte_size(symtab.getAddressWidth()){

  LOG(INFO) << "Binary is stripped: " << symtab.isStripped();
  LOG(INFO) << "Pie_mode: " << FLAGS_pie_mode;

  std::vector<SymtabAPI::Region *> regions;
  symtab.getAllRegions(regions);

  for (auto reg : regions) {
      gSectionManager->AddRegion(reg);
      if (reg->getMemOffset()) {
        gDisassContext->segment_eas.push_back(reg->getMemOffset());
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

  LOG_IF(WARNING, main_offset) << "Entrypoint was not found!";

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
    gDisassContext->func_map.insert({func->addr(), cfg_internal_func});
    LOG(INFO) << "Found internal function at 0x" << func->addr()
              << " with name " << cfg_internal_func->name();
  }

  // give entrypoint correct name, most likely main
  if (main_offset) {
    RenameFunc(main_offset, FLAGS_entrypoint);
  }

  // We need to give libc ctor/dtor names
  if (symtab.isStripped()) {
    if (ctor_offset) {
      RenameFunc(ctor_offset, "init");
    }
    if (dtor_offset) {
      RenameFunc(dtor_offset, "fini");
    }
  }

  GetNoReturns();

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
  gDisassContext->func_map.insert({func->addr(), cfg_internal_func});

  ParseAPI::Block *entryBlock = func->entry();
  cfg_internal_func->set_ea(entryBlock->start());

  cfg_internal_func->set_is_entrypoint(func);

  for (ParseAPI::Block *block : func->blocks()) {
    WriteBlock(block, func, cfg_internal_func);
  }

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
    gDisassContext->WriteAndAccount(a.second, true);
    code_object.parse(a.first, true);
  }

  for (auto func : code_object.funcs()) {
    auto code_xref = code_xrefs_to_resolve.find(func->addr());
    if (code_xref != code_xrefs_to_resolve.end() &&
        !gDisassContext->getInternalFunction(func->addr())) {

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

    auto old_set = inst_xrefs_to_resolve;
    inst_xrefs_to_resolve.clear();
    for (auto func : code_object.funcs()) {
      if (old_set.find(func->addr()) != old_set.end() &&
          !gDisassContext->getInternalFunction(func->addr())) {

        auto cfg_internal_func = module.add_funcs();
        WriteFunction(func, cfg_internal_func);
      }
    }
  }

  WriteLocalVariables();
  module.set_name(FLAGS_binary);
}

// TODO(lukas): Need to get all xrefs for local variable
void CFGWriter::WriteLocalVariables() {
  // We need to get SymtabAPI version of functions
  std::vector<SymtabAPI::Function *> funcs;
  symtab.getAllFunctions(funcs);
  for (auto func : funcs) {
    auto cfg_func = gDisassContext->func_map.find(func->getOffset());
    if (cfg_func == gDisassContext->func_map.end()) {
      continue;
    }

    std::vector<SymtabAPI::localVar *> locals;
    func->getLocalVariables(locals);

    // getParams resets the vector passed to it
    std::vector<SymtabAPI::localVar *> params;
    func->getParams(params);
    for (auto a : params) {
      locals.push_back(a);
    }

    for (auto local : locals) {
      auto cfg_var = cfg_func->second->add_stack_vars();
      cfg_var->set_name(local->getName());
      cfg_var->set_size(local->getType()->getSize());
      auto location_list = local->getLocationLists();

      LOG(INFO)
          << std::hex << "Found local variable with name " << local->getName()
          << " with size: " << local->getType()->getSize();

      for (auto &location : location_list) {
        cfg_var->set_sp_offset(location.frameOffset);
        LOG(INFO) << std::hex << "\tat sp_offset: 0x" << location.frameOffset;
      }

    }
  }
}

void CFGWriter::WriteExternalVariables() {
  std::vector<SymtabAPI::Symbol *> symbols;
  symbols = gSectionManager->GetExternalRelocs(
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
      auto external_var = magic_section.WriteExternalVariable(
          module, s->getMangledName());
      gDisassContext->external_vars.insert({external_var->ea(), external_var});
      continue;
    }

    auto external_var = module.add_external_vars();
    gDisassContext->external_vars.insert({s->getOffset(), external_var});
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
    if (!a->isInSymtab() || gDisassContext->external_vars.count(a->getOffset())) {
      continue;
    }
    if (a->getRegion() && (a->getRegion()->getRegionName() == ".bss" ||
                           a->getRegion()->getRegionName() == ".rodata")) {
      LOG(INFO) << "Found global variable " << a->getMangledName()
                << " at " << std::hex << a->getOffset() << std::dec;
      auto global_var = module.add_global_vars();
      global_var->set_ea(a->getOffset());
      global_var->set_name(a->getMangledName());
      global_var->set_size(a->getSize());
      gDisassContext->global_vars.insert({a->getOffset(), global_var});
    }
  }
}


// Get information from plt stubs about which external should be called.
// Other frontends do call to external rather than stub, so we should simulate
// this as well
void CFGWriter::SweepStubs() {
  for (ParseAPI::Function *func : code_object.funcs()) {
    if (gSectionManager->IsInRegions({".plt.got"}, func->entry()->start())) {
      auto inst =  func->entry()->getInsn(func->addr());
      if (inst->getCategory() == InstructionAPI::c_BranchInsn) {
        Dyninst::Address xref_addr = 0;
        TryEval(inst->getOperand(0).getValue().get(), func->addr(), xref_addr, inst->size());
        auto cfg_xref = gDisassContext->data_xrefs.find(xref_addr);
        if (cfg_xref == gDisassContext->data_xrefs.end()) {
          continue;
        }
        auto cfg_ext_func = gDisassContext->external_funcs.find(cfg_xref->second->target_ea());
        if (cfg_ext_func == gDisassContext->external_funcs.end()) {
          continue;
        }
        magic_section.AllocSpace(func->addr(), cfg_ext_func->second->ea());
        gDisassContext->external_funcs.insert({func->addr(), cfg_ext_func->second});
      }
    }
  }
}


void CFGWriter::WriteInternalFunctions() {
    // I don't want this to be in recompiled binary as compiler will
    // add them as well, sub_* is enough
    std::unordered_set< std::string > not_entrypoints = {
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
    else if (gSectionManager->IsInRegions({".got.plt", "plt.got"},
                                          func->entry()->start())) {
     LOG(INFO) << "Function " << func->name()
               << " is getting skipped because it is .got.plt stub";
      continue;
    }

    auto cfg_internal_func = gDisassContext->getInternalFunction(func->addr());

    ParseAPI::Block *entryBlock = func->entry();
    CHECK(entryBlock->start() == cfg_internal_func->ea())
        << "Start of the block is not equal to function ea";

    cfg_internal_func->set_is_entrypoint(
        not_entrypoints.find(func->name()) == not_entrypoints.end());

    for (ParseAPI::Block *block : func->blocks()) {
      WriteBlock(block, func, cfg_internal_func);
    }
  }
}


//TODO(lukas): This one is basically unchanged from original PR.
void CFGWriter::WriteBlock(ParseAPI::Block *block, ParseAPI::Function *func,
                           mcsema::Function *cfg_internal_func) {

  mcsema::Block *cfg_block = cfg_internal_func->add_blocks();
  cfg_block->set_ea(block->start());

  // Set outgoing edges
  std::set<Address> successors;
  for (auto edge : block->targets()) {

    // Is this block part of the current function?
    bool found = false;

    for (auto bl : func->blocks()) {
      if (bl->start() == edge->trg()->start()) {
        found = true;
        break;
      }
    }

    if ((!found) || (edge->trg()->start() == -1)) {
      continue;
    }

    // Handle recursive calls
    found = false;

    if (edge->trg()->start() == func->entry()->start()) {
      for (auto call_edge : func->callEdges()) {
        if ((call_edge->src()->start() == block->start()) &&
            (call_edge->trg()->start() == func->entry()->start())) {
          // Looks like a recursive call, so no block_follows edge here
          found = true;
          break;
        }
      }
    }

    if (!found) {
      // TODO(lukas): Exception handling
      // For now ignore catch blocks
      LOG(INFO) << "Edge 0x" << std::hex << block->start()
                << " -> 0x" << edge->trg()->start()
                << " of type " << edge->type();
      if (edge->type() != Dyninst::ParseAPI::EdgeTypeEnum::CATCH &&
          edge->type() != Dyninst::ParseAPI::EdgeTypeEnum::RET &&
          edge->type() != Dyninst::ParseAPI::EdgeTypeEnum::CALL) {
        successors.insert(edge->trg()->start());
        cfg_block->add_successor_eas(edge->trg()->start());
      }
    }
  }


  // Write instructions
  std::map<Offset, InstructionAPI::Instruction::Ptr> instructions;
  block->getInsns(instructions);

  Address ip = block->start();

  for (auto p = instructions.begin(); p != instructions.end();) {
    InstructionAPI::Instruction *instruction = p->second.get();

    WriteInstruction(instruction, ip, cfg_block, (++p) == instructions.end());
    ip += instruction->size();
  }

  LOG(INFO) << "Block at 0x" << std::hex << block->start() << std::dec
            << " has " << successors.size() << " successors";

  ResolveOffsetTable(successors, cfg_block, offset_tables);
}

void CFGWriter::WriteInstruction(InstructionAPI::Instruction *instruction,
                                 Address addr, mcsema::Block *cfg_block,
                                 bool is_last) {

  mcsema::Instruction *cfg_instruction = cfg_block->add_instructions();

  std::string instBytes;
  for (int offset = 0; offset < instruction->size(); ++offset) {
    instBytes += (int)instruction->rawByte(offset);
  }

  cfg_instruction->set_bytes(instBytes);
  cfg_instruction->set_ea(addr);

  std::vector<InstructionAPI::Operand> operands;
  instruction->getOperands(operands);

  if (instruction->getCategory() == InstructionAPI::c_CallInsn) {
    HandleCallInstruction(instruction, addr, cfg_instruction, is_last);
  } else {
    HandleNonCallInstruction(instruction, addr, cfg_instruction, cfg_block, is_last);
  }

  code_xrefs_to_resolve.erase(addr);
}


void WriteDisplacement(mcsema::Instruction *cfg_instruction, Address &address) {

  if (gDisassContext->HandleCodeXref(
      {static_cast<Address>(cfg_instruction->ea()),
      address, cfg_instruction})) {

    auto cfg_xref =
        cfg_instruction->mutable_xrefs(cfg_instruction->xrefs_size() - 1);
    cfg_xref->set_operand_type(CodeReference::MemoryDisplacementOperand);
  }
}

// For instruction to have MemoryDisplacement it has among other things
// be of type BinaryFunction
Address DisplacementHelper(Dyninst::InstructionAPI::Expression *expr) {
  if (auto bin_func = dynamic_cast<InstructionAPI::BinaryFunction *>(expr)) {
    std::vector<InstructionAPI::InstructionAST::Ptr> inner_operands;
    bin_func->getChildren(inner_operands);

    for (auto &inner_op : inner_operands) {
      if (auto imm = dynamic_cast<InstructionAPI::Immediate *>(inner_op.get())) {
        return imm->eval().convert<Address>();
      }
    }
  }
  return 0;
}

void CFGWriter::CheckDisplacement(Dyninst::InstructionAPI::Expression *expr,
                                  mcsema::Instruction *cfg_instruction) {

  //TODO(lukas): This is possibly incorrect attempt to cull down amount of
  //             "false" xrefs of type MemoryDisplacement
  if (cfg_instruction->xrefs_size()) {
    LOG(INFO) << "Avoiding clobbering with xrefs 0x"
              << std::hex << cfg_instruction->ea();
    return;
  }
  if (auto deref = dynamic_cast<InstructionAPI::Dereference *>(expr)) {
    std::vector<InstructionAPI::InstructionAST::Ptr> inner_operands;
    deref->getChildren(inner_operands);

    for (auto &op : inner_operands) {
      if (auto inner_expr =
              dynamic_cast<InstructionAPI::Expression *>(op.get())) {
        auto displacement = DisplacementHelper(inner_expr);
        if (displacement) {
          WriteDisplacement(cfg_instruction, displacement);
        }
      }
    }
  } else {
    if (auto displacement = DisplacementHelper(expr)) {
      WriteDisplacement(cfg_instruction, displacement);
    }
  }
}

void CFGWriter::GetNoReturns() {
  for (auto f : code_object.funcs()) {
    if (f->retstatus() == ParseAPI::NORETURN) {
      no_ret_funcs.insert(f->name());
    }
  }
}

bool CFGWriter::IsNoReturn(const std::string &name) {
  return no_ret_funcs.find(name) != no_ret_funcs.end();
}


//TODO(lukas): This is hacky
void CFGWriter::HandleCallInstruction(InstructionAPI::Instruction *instruction,
                                      Address addr,
                                      mcsema::Instruction *cfg_instruction,
                                      bool is_last) {
  Address target;
  std::vector<InstructionAPI::Operand> operands;
  instruction->getOperands(operands);

  Address size = instruction->size();

  LOG(INFO) << "Trying to resolve call instruction at 0x"
            << std::hex << cfg_instruction->ea();
  LOG(INFO) << instruction->format();
  if (TryEval(operands[0].getValue().get(), addr, target, size)) {
    HandleXref(cfg_instruction, target);

    // What can happen is that we get xref somewhere in the .text and HandleXref
    // fills it with defaults. We need to check and correct it if needed
    if (gSectionManager->IsInRegion(".text", target)) {
      auto xref = cfg_instruction->mutable_xrefs(0);

      //xref->set_target_type(CodeReference::CodeTarget);
      xref->set_operand_type(CodeReference::ControlFlowOperand);

      // It is pointing in .text and not to a function?
      // That's weird, quite possibly we are missing a function!
      if (!gDisassContext->getInternalFunction(target)) {
        LOG(INFO) << "Unresolved inst_xref " << target;
        inst_xrefs_to_resolve.insert(
          {target , {addr, target, cfg_instruction}});
      }
    }

    if (IsNoReturn(cfg_instruction->mutable_xrefs(0)->name())) {
      cfg_instruction->set_local_noreturn(true);
    }
    return;
  }
}

Address CFGWriter::immediateNonCall(InstructionAPI::Immediate* imm,
                                    Address addr,
                                    mcsema::Instruction* cfg_instruction ) {

  Address a = imm->eval().convert<Address>();
  if (!gDisassContext->HandleCodeXref({addr, a, cfg_instruction}, false)) {
    if (gSectionManager->IsInRegion(".text", a)) {
      AddCodeXref(cfg_instruction,
        CodeReference::DataTarget,
        CodeReference::ImmediateOperand,
        CodeReference::Internal,
        a);
      LOG(INFO) << std::hex
                << "IMM may be working with new function starting at" << a;
      inst_xrefs_to_resolve.insert({a, {}});
      return a;
    }
    LOG(INFO) << "Not forcing target 0x" << std::hex << a;
    return 0;
  }
  auto cfg_code_xref = cfg_instruction->mutable_xrefs(cfg_instruction->xrefs_size() - 1);
  cfg_code_xref->set_operand_type(CodeReference::ImmediateOperand);
  return a;

}

Address CFGWriter::dereferenceNonCall(InstructionAPI::Dereference* deref,
                                   Address addr,
                                   mcsema::Instruction* cfg_instruction) {

  std::vector<InstructionAPI::InstructionAST::Ptr> children;
  deref->getChildren(children);
  auto expr = dynamic_cast<InstructionAPI::Expression *>(children[0].get());

  CHECK(expr) << "Expected expression";

  Address a;
  // TODO(lukas): Possibly may discover new functions?
  if (TryEval(expr, addr, a)) {
    gDisassContext->HandleCodeXref({addr, a, cfg_instruction});
    return a;
  }

  return 0;
}

//TODO(lukas): Remove
bool CFGWriter::HandleXref(mcsema::Instruction *cfg_instruction,
                           Address addr,
                           bool force) {
  if (gDisassContext->HandleCodeXref({0, addr, cfg_instruction}, false)) {
    return true;
  }

  if (gSectionManager->IsInRegion(".text", addr) &&
      !gDisassContext->getInternalFunction(addr)) {
    inst_xrefs_to_resolve.insert({addr, {static_cast<Dyninst::Address>(cfg_instruction->ea()),
                                         addr, cfg_instruction}});
  }

  return gDisassContext->HandleCodeXref({0, addr, cfg_instruction}, force);
}

void CFGWriter::HandleNonCallInstruction(
    Dyninst::InstructionAPI::Instruction *instruction,
    Address addr,
    mcsema::Instruction *cfg_instruction,
    mcsema::Block *cfg_block,
    bool is_last) {


  if (FLAGS_pie_mode && instruction->getOperation().getID() == entryID::e_test) {
    LOG(INFO) << std::hex << "Shouldn't contain xref at 0x"
              << addr << std::dec << ": " << instruction->format();
    return;
  }

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
      if (FLAGS_pie_mode) {
        if (instruction->getOperation().getID() != entryID::e_cmp &&
            instruction->getOperation().getID() != entryID::e_and) {
          direct_values[i] = immediateNonCall(imm, addr, cfg_instruction);
        } else {
          direct_values[i] = 0;
        }
      } else {
          direct_values[i] = immediateNonCall(imm, addr, cfg_instruction);
      }
    } else if (
        auto deref = dynamic_cast<InstructionAPI::Dereference *>(expr.get())) {
      LOG(INFO) << "\tDealing with Dereference as op";
      direct_values[i] = dereferenceNonCall(deref, addr, cfg_instruction);

    } else if (
        auto bf = dynamic_cast<InstructionAPI::BinaryFunction *>(expr.get())) {
      LOG(INFO) << "Dealing with BinaryFunction as op";

      auto instruction_id = instruction->getOperation().getID();
      if (instruction_id == entryID::e_lea) {
        Address a;

        if(TryEval(expr.get(), addr, a)) {
          HandleXref(cfg_instruction, a);

          if (gSectionManager->IsInRegion(".text", a)) {
            // get last one and change it to code
            auto xref = cfg_instruction->mutable_xrefs(
                cfg_instruction->xrefs_size() - 1);
            xref->set_operand_type(CodeReference::MemoryOperand);
          }
          direct_values[i] = a;
        }

      } else if (instruction->getCategory() == InstructionAPI::c_BranchInsn) {
        Address a;
        // This has + |instruction| in AST
        if (TryEval(expr.get(), addr - instruction->size(), a)) {
          LOG(INFO) << "Eval'd as " << a;
          if (is_last) {
            for (auto succ : cfg_block->successor_eas()) {
              if (a == succ) {
                AddCodeXref(cfg_instruction,
                            mcsema::CodeReference::CodeTarget,
                            mcsema::CodeReference::ControlFlowOperand,
                            mcsema::CodeReference::Internal,
                            a);
              }
            }
          }
          // ea is not really that important
          // in CrossXref<mcsema::Instruction *>
          if (gDisassContext->HandleCodeXref({0, a, cfg_instruction})) {
            auto cfg_xref = cfg_instruction->mutable_xrefs(
                cfg_instruction->xrefs_size() - 1);
            cfg_xref->set_target_type(CodeReference::CodeTarget);
            cfg_xref->set_operand_type(CodeReference::ControlFlowOperand);
          }
          direct_values[i] = a;
        }
      }
    }
    ++i;
    CheckDisplacement(expr.get(), cfg_instruction);
  }

  // We may be storing some address wich is quite possibly entrypoint of
  // something we should treat as function in cfg
  if (direct_values[0] && direct_values[1]) {
    addr -= instruction->size();
    bool is_in_data = gSectionManager->IsInRegions(
        {".bss", ".data", ".rodata"},
        direct_values[0]);

    if (gSectionManager->IsInRegion(".text", direct_values[1]) &&
        is_in_data) {

      if (!gDisassContext->getInternalFunction(direct_values[0])) {
        LOG(INFO)
            << "\tAnd it is not parsed yet, storing it to be resolved later!";
        inst_xrefs_to_resolve.insert({direct_values[1], {}});
      }
    }
  }
}

void CFGWriter::WriteExternalFunctions() {
  std::vector<std::string> unknown;
  auto symbols = gSectionManager->GetExternalRelocs(
      Dyninst::SymtabAPI::Symbol::SymbolType::ST_FUNCTION);

  auto known = gExtFuncManager->GetAllUsed( unknown );
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

    LOG_IF(WARNING, !found) << "External function was not found in CodeSource::linkage()";

    func.ea = a;
    auto cfg_external_func = magic_section.WriteExternalFunction(module, func);
    gDisassContext->external_funcs.insert({a, cfg_external_func});
  }
}

void WriteRawData(std::string& data, SymtabAPI::Region* region) {
  auto i = 0U;

  for (; i < region->getDiskSize(); ++i) {
    data += ((const char *)region->getPtrToRawData())[i];
  }

  // Zero padding
  for (; i < region->getMemSize(); ++i) {
    data += '\0';
  }
}

// Writes into section on specified offset
// If offset points beyond section, it is resized to contain it
void WriteAsRaw(std::string& data, uint64_t number, int64_t offset) {

  if (offset < 0) {
    LOG(FATAL) << "Trying yo Write raw on negative offset";
  }

  if (offset + 3 >= data.size()) {
    LOG(WARNING) << "AsRaw would overWrite stuff";
    data.resize(offset + 3, '\0');
  }

  for (int i = 0; i < 4; ++i) {
    data[offset + i] = (number >> (i * 8));
  }
}

//TODO(lukas): Relic of old PR, not sure if needed
//             -fPIC & -pie?
void CFGWriter::WriteGOT(SymtabAPI::Region* region,
                                 mcsema::Segment* cfg_segment) {
  auto rela_dyn = gSectionManager->GetRegion(".rela.dyn");

  if (!rela_dyn) {
    return;
  }
  const auto &relocations = rela_dyn->getRelocations();

  auto old_data = cfg_segment->mutable_data();
  std::string data{*old_data};
  for (auto reloc : relocations) {
    if (!gSectionManager->IsInRegion(region, reloc.rel_addr())) {
      continue;
    }

    bool found = false;
    LOG(INFO) << "Trying to resolve reloc " << reloc.name();

    for (auto ext_var : magic_section.ext_vars) {
      if (reloc.name() == ext_var->name()) {
        LOG(INFO) << "Writing cfg_xref in got 0x" << std::hex
                  << reloc.rel_addr() << " -> 0x" << ext_var->ea();
        auto cfg_xref = gDisassContext->WriteAndAccount({
             reloc.rel_addr(),
             static_cast<Dyninst::Address>(ext_var->ea()),
             cfg_segment,
             ext_var->name()}, false);
        found = true;
        gDisassContext->data_xrefs.insert({reloc.rel_addr(), cfg_xref});
        WriteAsRaw(data, ext_var->ea(), reloc.rel_addr() - cfg_segment->ea());
      }
    }
    if (!found && !reloc.name().empty()) {
      LOG(WARNING)
          << "Giving magic_space to" << reloc.name();

      auto unreal_ea = magic_section.AllocSpace(ptr_byte_size);
      gDisassContext->WriteAndAccount(
          {reloc.rel_addr(), unreal_ea, cfg_segment, reloc.name()},
          true);
      WriteAsRaw(data, unreal_ea, reloc.rel_addr() - cfg_segment->ea());

    if (gExtFuncManager->IsExternal(reloc.name())) {
        auto func = gExtFuncManager->GetExternalFunction(reloc.name());
        func.imag_ea = unreal_ea;
        auto cfg_func = func.WriteHelper(module, unreal_ea);
        gDisassContext->external_funcs.insert({unreal_ea, cfg_func});
      }
    }
  }
  for (auto i = 0U; i < data.size(); ++i) {
    LOG(INFO) << std::hex << +static_cast<uint8_t>((data)[i]);
  }
  cfg_segment->set_data(data);
}

void CFGWriter::WriteRelocations(SymtabAPI::Region* region,
                         mcsema::Segment *segment) {

  auto rela_dyn = gSectionManager->GetRegion(".rela.plt");
  if (!rela_dyn) {
    return;
  }
  const auto &relocations = rela_dyn->getRelocations();
  auto data = segment->mutable_data();

  for (auto reloc : relocations) {
    LOG(INFO) << "Trying to resolve reloc " << reloc.name();
    for (auto ext_func : magic_section.ext_funcs) {
      if (reloc.name() == ext_func->name()) {
        LOG(INFO) << "Writing xref in got 0x" << std::hex
                  << reloc.rel_addr() << " -> 0x" << ext_func->ea();
        gDisassContext->WriteAndAccount({
            reloc.rel_addr(),
            static_cast<Dyninst::Address>(ext_func->ea()),
            segment,
            ext_func->name()});
        WriteAsRaw(*data, ext_func->ea(), reloc.rel_addr() - segment->ea());
      }
    }
  }
}

void WriteBssXrefs(
    SymtabAPI::Region *region,
    mcsema::Segment *segment,
    const DisassContext::SymbolMap<mcsema::ExternalVariable *> &externals) {
  for (auto &external : externals) {
    if (gSectionManager->IsInRegion(region, external.first)) {
      gDisassContext->WriteAndAccount(
          {external.first, external.first, segment, external.second->name()},
          false/*, external.second->size()*/);
    }
  }
}

// Write content of sections, try to parse for xrefs and vars
// .rodata, .data have special treatment, since there can be string
// variables and such
// Writes things into gDisassContext
void CFGWriter::WriteInternalData() {
  auto dataRegions = gSectionManager->GetDataRegions();
  SectionParser section_parser(gDisassContext.get(), *gSectionManager);

  for (auto region : dataRegions) {

    // IDA does not include some of these, so neither should we
    std::set<std::string> no_parse = {
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
    LOG(INFO) << "Passed sanity check " << region->getRegionName();

    if (region->getRegionName() == ".fini_array") {
      continue;
    }
    auto cfg_internal_data = module.add_segments();
    gSectionManager->SetCFG(region, cfg_internal_data);

    std::string data;
    WriteRawData(data, region);

    // .init & .fini should be together
    if (region->getRegionName() == ".init_array") {
      SymtabAPI::Region* fini;
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
    cfg_internal_data->set_is_exported(false);      /* TODO: As for now, ignored */
    cfg_internal_data->set_is_thread_local(false); /* TODO: As for now, ignored */

    std::set<std::string> dont_parse = {
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

      section_parser.XrefsInSegment( region, cfg_internal_data );
    }

    // IDA output of .bss produced some "self xrefs"
    if (region->getRegionName() == ".bss") {
      WriteBssXrefs(region, cfg_internal_data, gDisassContext->external_vars);
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

      if (gDisassContext->external_vars.find(a->getOffset()) !=
          gDisassContext->external_vars.end() ||
          gDisassContext->segment_vars.count(a->getOffset())) {
        continue;
      }

      // TODO(lukas): Var recovery related
      /*
      auto var = segment->add_vars();
      var->set_ea(a->getOffset());
      var->set_name(a->getMangledName());
      LOG(INFO) << "Added var 0x" << std::hex << a->getOffset();
      gDisassContext->segment_vars.insert({a->getOffset(), var});
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
  return gDisassContext->external_vars.find(addr) != gDisassContext->external_vars.end() ||
         gDisassContext->external_funcs.find(addr) != gDisassContext->external_funcs.end();
}