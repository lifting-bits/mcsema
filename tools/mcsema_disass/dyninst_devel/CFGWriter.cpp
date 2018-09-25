#include "CFGWriter.h"

#include <Dereference.h>
#include <Function.h>
#include <Instruction.h>
#include <InstructionAST.h>
#include <InstructionCategories.h>
#include <sstream>

#include <array>
#include <iterator>

#include <ArchSpecificFormatters.h>

#include <glog/logging.h>
#include <gflags/gflags.h>

#include "Util.h"
#include <cstdio>
DECLARE_string(entrypoint);

DECLARE_bool(pie_mode);

using namespace Dyninst;
using namespace mcsema;

mcsema::Module gModule;

namespace {

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
      auto rip = mov_inst->first;
      if (mov_inst->second->getOperation().getID() == 268) {
        rip += mov_inst->second->size();
      }
      if (!TryEval(second_operand.getValue().get(), rip, offset, mov_inst->second->size())) {
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

void WriteDataXref(const CrossXref<mcsema::Segment *> &xref,
                   const std::string &name="",
                   bool is_code=false,
                   uint64_t width=8) {

  auto cfg_xref = xref.WriteDataXref(name, is_code, width);
  gDisassContext->data_xrefs.insert({static_cast<Dyninst::Address>(xref.ea), cfg_xref});
}


//TODO(lukas): Investigate, this ignores .bss?
/*
bool IsInBinary(ParseAPI::CodeSource &code_source, Address a) {
  for (auto &r : gSectionManager->GetDataRegions()) {
    if (IsInRegion(r, a)) {
      return true;
    }
  }
  LOG(INFO) << std::hex << a << std::dec << " is not contained in code_source";
  return false;
}
*/
// Modifies gDisassContext
void RenameFunc(Dyninst::Address ea, const std::string& new_name) {
  LOG(INFO) << "Renaming 0x:" << std::hex << ea << " to " << new_name;
  auto internal_func = gDisassContext->getInternalFunction(ea);
  if (!internal_func) {
    return;
  }
  internal_func->set_name(new_name);
}

} //namespace

CFGWriter::CFGWriter(mcsema::Module &m, const std::string &module_name,
                     SymtabAPI::Symtab &symtab,
                     ParseAPI::SymtabCodeSource &symCodeSrc,
                     ParseAPI::CodeObject &codeObj)
    : module(m),
      module_name(module_name),
      symtab(symtab),
      code_source(symCodeSrc),
      code_object(codeObj),
      magic_section(gDisassContext->magic_section),
      ptr_byte_size(symtab.getAddressWidth()){

  LOG(INFO) << "Binary is stripped: " << symtab.isStripped();

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
  if (ctor_offset) {
    RenameFunc(ctor_offset, "init");
  }
  if (dtor_offset) {
    RenameFunc(dtor_offset, "fini");
  }

  getNoReturns();

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

void CFGWriter::writeFunction(Dyninst::ParseAPI::Function *func,
                              mcsema::Function *cfg_internal_func) {
  gDisassContext->func_map.insert({func->addr(), cfg_internal_func});

  ParseAPI::Block *entryBlock = func->entry();
  cfg_internal_func->set_ea(entryBlock->start());

  cfg_internal_func->set_is_entrypoint(func);

  for (ParseAPI::Block *block : func->blocks()) {
    writeBlock(block, func, cfg_internal_func);
  }

  cfg_internal_func->set_name(func->name());
  LOG(INFO) << "Added " << func->name() << " into module, found via xref";
}

void CFGWriter::write() {
  writeExternalFunctions();
  writeExternalVariables();
  writeInternalData();
  writeGlobalVariables();

  writeInternalFunctions();

  //Handle new functions found via various xrefs, mostly in stripped binary
  LOG(INFO) << code_xrefs_to_resolve.size() << " code xrefs is unresolved!";
  for (auto &a : code_xrefs_to_resolve) {
    WriteDataXref(a.second, "", true);
    code_object.parse(a.first, true);
  }

  for (auto func : code_object.funcs()) {
    auto code_xref = code_xrefs_to_resolve.find(func->addr());
    if (code_xref != code_xrefs_to_resolve.end() &&
        !gDisassContext->getInternalFunction(func->addr())) {

      auto cfg_internal_func = module.add_funcs();
      writeFunction(func, cfg_internal_func);
    }
  }

  // In case we discovered some new ones, we need to try until fixpoint
  while (!inst_xrefs_to_resolve.empty()) {
    LOG(WARNING) << inst_xrefs_to_resolve.size() << " inst code xrefs is unresolved!";
    for (auto &a : inst_xrefs_to_resolve) {
      code_object.parse(a.first, false);
    }

    auto old_set = inst_xrefs_to_resolve;
    inst_xrefs_to_resolve.clear();
    for (auto func : code_object.funcs()) {
      if (old_set.find(func->addr()) != old_set.end() &&
          !gDisassContext->getInternalFunction(func->addr())) {

        auto cfg_internal_func = module.add_funcs();
        writeFunction(func, cfg_internal_func);
      }
    }
  }
  module.set_name(module_name);
}

void CFGWriter::writeExternalVariables() {
  std::vector<SymtabAPI::Symbol *> symbols;
  symtab.getAllSymbolsByType(symbols, SymtabAPI::Symbol::ST_OBJECT);

  LOG(INFO) << "Writing " << symbols.size() << " external variables";
  for (const auto &s : symbols) {
    if (s->isInDynSymtab()) {
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
      external_var->set_is_weak(false);
      external_var->set_is_thread_local(false);
    }
  }
}

void CFGWriter::writeGlobalVariables() {
  std::vector<SymtabAPI::Symbol *> vars;
  for (auto &a : vars) {
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

void CFGWriter::writeInternalFunctions() {
    // I don't want this to be in recompiled binary as compiler will
    // add them as well, sub_* is enough
    std::unordered_set< std::string > notEntryPoints = {
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
   if (isExternal(func->entry()->start())) {
     LOG(INFO) << "Function " << func->name() << " is getting skipped";
     continue;
   }
    // We want to ignore the .got.plt stubs, since they are not needed
    // and cfg file would grow significantly
    else if (gSectionManager->IsInRegion(".got.plt",
                                          func->entry()->start())) {
     LOG(INFO) << "Function " << func->name()
               << " is getting skipped because it is .got.pl stub";
      continue;
    }

    auto cfg_internal_func = gDisassContext->getInternalFunction(func->addr());

    ParseAPI::Block *entryBlock = func->entry();
    CHECK(entryBlock->start() == cfg_internal_func->ea())
        << "Start of the block is not equal to function ea";

    cfg_internal_func->set_is_entrypoint(
        notEntryPoints.find(func->name()) == notEntryPoints.end());
    LOG(INFO) << "Function " << cfg_internal_func->name() << " at 0x"
              << std::hex << cfg_internal_func->ea()
              << " is entry point? "<< cfg_internal_func->is_entrypoint();

    for (ParseAPI::Block *block : func->blocks()) {
      writeBlock(block, func, cfg_internal_func);
    }
  }
}


//TODO(lukas): This one is basically unchanged from original PR.
void CFGWriter::writeBlock(ParseAPI::Block *block, ParseAPI::Function *func,
                           mcsema::Function *cfg_internal_func) {

  mcsema::Block *cfg_block = cfg_internal_func->add_blocks();
  cfg_block->set_ea(block->start());

  // Set outgoing edges
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
      for (auto callEdge : func->callEdges()) {
        if ((callEdge->src()->start() == block->start()) &&
            (callEdge->trg()->start() == func->entry()->start())) {
          // Looks like a recursive call, so no block_follows edge here
          found = true;
          break;
        }
      }
    }

    if (!found)
      cfg_block->add_successor_eas(edge->trg()->start());
  }

  // Write instructions

  std::map<Offset, InstructionAPI::Instruction::Ptr> instructions;
  block->getInsns(instructions);

  Address ip = block->start();

  for (auto p : instructions) {
    InstructionAPI::Instruction *instruction = p.second.get();

    writeInstruction(instruction, ip, cfg_block);
    ip += instruction->size();
  }

}

void CFGWriter::writeInstruction(InstructionAPI::Instruction *instruction,
                                 Address addr, mcsema::Block *cfg_block) {

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
    handleCallInstruction(instruction, addr, cfg_instruction);
  } else {
    handleNonCallInstruction(instruction, addr, cfg_instruction);
  }
  //TODO(lukas): We just found it, no need to bother with it?
  //             But what if it needs to be start of function?
  code_xrefs_to_resolve.erase(addr);
}


void writeDisplacement(mcsema::Instruction *cfg_instruction, Address &address,
        const std::string& name = "") {
  // Addres is uint64_t and in CFG ea is int64_t
  if (static_cast<int64_t>(address) <= 0) {
    return;
  }

  AddCodeXref( cfg_instruction, CodeReference::DataTarget,
          CodeReference::MemoryDisplacementOperand, CodeReference::Internal,
          address, name );
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

// TODO(lukas): It has to actually point at something to be MDO
void CFGWriter::checkDisplacement(Dyninst::InstructionAPI::Expression *expr,
                       mcsema::Instruction *cfg_instruction) {

  //TODO(lukas): This is possibly incorrect attempt to cull down amount of
  //             "false" xrefs of type MemoryDisplacement
  if (cfg_instruction->xrefs_size()) {
    LOG(INFO) << "Avoiding clobbering with xrefs!";
    return;
  }
  if (auto deref = dynamic_cast<InstructionAPI::Dereference *>(expr)) {
    std::vector<InstructionAPI::InstructionAST::Ptr> inner_operands;
    deref->getChildren(inner_operands);

    for (auto &op : inner_operands) {
      if (auto inner_expr = dynamic_cast<InstructionAPI::Expression *>(op.get())) {
        auto displacement = DisplacementHelper(inner_expr);
        if (displacement) {
          writeDisplacement(cfg_instruction, displacement);
        }
      }
    }
  } else {
    if (auto displacement = DisplacementHelper(expr)) {
      writeDisplacement(cfg_instruction, displacement);
    }
  }
}

void CFGWriter::getNoReturns() {
  for (auto f : code_object.funcs()) {
    if (f->retstatus() == ParseAPI::NORETURN) {
      no_ret_funcs.insert(f->name());
    }
  }
}

bool CFGWriter::isNoReturn(const std::string &name) {
  return no_ret_funcs.find(name) != no_ret_funcs.end();
}

//TODO(lukas): This one should be replaced in favor of
//             function of the type handleXref or FishFor*
std::string CFGWriter::getXrefName(Address addr) {
  auto func = gDisassContext->func_map.find(addr);
  if (func != gDisassContext->func_map.end()) {
    return func->second->name();
  }

  auto extVar = gDisassContext->external_vars.find(addr);
  if (extVar != gDisassContext->external_vars.end()) {
    return extVar->second->name();
  }

  auto globalVar = gDisassContext->global_vars.find(addr);
  if (globalVar != gDisassContext->global_vars.end()) {
    return globalVar->second->name();
  }


  auto segmentVar = gDisassContext->segment_vars.find(addr);
  if (segmentVar != gDisassContext->segment_vars.end()) {
    return segmentVar->second->name();
  }

  // Sometimes things have no name but they are still xrefs
  // We could leave the name empty as well
  return "__mcsema_unknown";
}

//TODO(lukas): This is hacky af
void CFGWriter::handleCallInstruction(InstructionAPI::Instruction *instruction,
                                      Address addr,
                                      mcsema::Instruction *cfg_instruction) {
  Address target;
  std::vector<InstructionAPI::Operand> operands;
  instruction->getOperands(operands);

  Address size = instruction->size();

  LOG(INFO) << "TryEval " << addr << " " << size;
  bool got_result = false;
  if (TryEval(operands[0].getValue().get(), addr, target, size)) {
    handleXref(cfg_instruction, target);

    // What can happen is that we get xref somewhere in the .text and handleXref
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

    if (isNoReturn(cfg_instruction->mutable_xrefs(0)->name())) {
      cfg_instruction->set_local_noreturn(true);
    }
    return;
  }
}

Address CFGWriter::immediateNonCall( InstructionAPI::Immediate* imm,
        Address addr, mcsema::Instruction* cfg_instruction ) {

  Address a = imm->eval().convert<Address>();
  if (!gDisassContext->HandleCodeXref({addr, a, cfg_instruction}, false)) {
    if (gSectionManager->IsInRegion(".text", a)) {
      auto cfgCodeRef = AddCodeXref(cfg_instruction,
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

// Handling only CODEXREFS!
// TODO(lukas): gDisassContext should be responsible for this
bool CFGWriter::handleXref(mcsema::Instruction *cfg_instruction,
                           Address addr,
                           bool force) {

  return gDisassContext->HandleCodeXref({0, addr, cfg_instruction}, force);
}

void CFGWriter::handleNonCallInstruction(
    Dyninst::InstructionAPI::Instruction *instruction,
    Address addr,
    mcsema::Instruction *cfg_instruction) {

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
  LOG(INFO) << instruction->format() << " at 0x" << std::hex << addr - instruction->size();
  for (auto op : operands) {
    auto expr = op.getValue();
    if (auto imm = dynamic_cast<InstructionAPI::Immediate *>(expr.get())) {
      LOG(INFO) << "\tDealing with Immidiate as op";
      direct_values[i] = immediateNonCall(imm, addr, cfg_instruction);
    } else if (
        auto deref = dynamic_cast<InstructionAPI::Dereference *>(expr.get())) {
      LOG(INFO) << "\tDealing with Dereference as op";
      direct_values[i] = dereferenceNonCall(deref, addr, cfg_instruction);
    } else if (
        auto bf = dynamic_cast<InstructionAPI::BinaryFunction *>(expr.get())) {
      LOG(INFO) << "Dealing with BinaryFunction as op";

      // 268 stands for lea
      auto instruction_id = instruction->getOperation().getID();
      if (instruction_id == 268) {
        Address a;

        if(TryEval(expr.get(), addr, a)) {
          handleXref(cfg_instruction, a);
          if (gSectionManager->IsInRegion(".text", a)) {
            // get last one and change it to code
            auto xref = cfg_instruction->mutable_xrefs(cfg_instruction->xrefs_size() - 1);
            xref->set_operand_type(CodeReference::MemoryOperand);
          }
          direct_values[i] = a;
        }
      } else if (instruction->getCategory() == InstructionAPI::c_BranchInsn) {
        Address a;
        // This has + |instruction| in AST
        if (TryEval(expr.get(), addr - instruction->size(), a)) {
          if (gDisassContext->HandleCodeXref({0, a, cfg_instruction})) {
            auto cfg_xref = cfg_instruction->mutable_xrefs(cfg_instruction->xrefs_size() - 1);
            cfg_xref->set_target_type(CodeReference::CodeTarget);
            cfg_xref->set_operand_type(CodeReference::ControlFlowOperand);
          }
          direct_values[i] = a;
        }
      }
    }
    ++i;
    checkDisplacement(expr.get(), cfg_instruction);
  }

  // We may be storing some address wich is quite possibly entrypoint of
  // something we should treat as function in cfg
  if (direct_values[0] && direct_values[1]) {
    addr -= instruction->size();
    bool is_somewhere_reasonable = gSectionManager->IsInRegions(
        {".bss", ".data", ".rodata"},
        direct_values[0]);
    if (gSectionManager->IsInRegion(".text", direct_values[1]) &&
        is_somewhere_reasonable) {
      if (!gDisassContext->getInternalFunction(direct_values[0])) {
        LOG(INFO)
            << "\tAnd it is not parsed yet, storing it to be resolved later!";
        inst_xrefs_to_resolve.insert({direct_values[1], {}});
      }
    }
  }
}

void CFGWriter::writeExternalFunctions() {
  std::vector<std::string> unknown;
  auto known = gExt_func_manager->GetAllUsed( unknown );
  LOG(INFO) << "Found " << known.size() << " external functions";

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

    CHECK(found) << "External function was not found in CodeSource::linkage()";

    func.ea = a;
    auto cfg_external_func = magic_section.WriteExternalFunction(module, func);
    gDisassContext->external_funcs.insert({a, cfg_external_func});
  }
}

bool CFGWriter::handleDataXref(const CrossXref<mcsema::Segment *> &xref) {
  return handleDataXref(xref.segment, xref.ea, xref.target_ea);
}

bool CFGWriter::handleDataXref(mcsema::Segment *segment,
                               Address ea,
                               Address target) {
  CrossXref<mcsema::Segment *> context_xref = {ea, target, segment};

  // segment_vars, external_vars, global_vars
  if (gDisassContext->HandleDataXref(context_xref)) {
    return true;
  }
  return false;
}

//TODO(lukas): This is finding vars actually?
void CFGWriter::tryParseVariables(SymtabAPI::Region *region, mcsema::Segment *segment) {
  std::string base_name = region->getRegionName();
  auto offset = static_cast<uint8_t *>(region->getPtrToRawData());
  auto end = region->getMemOffset() + region->getMemSize();

  LOG(INFO) << "Trying to parse region " << region->getRegionName()
            << " for xrefs & vars";
  LOG(INFO) << "Starts at 0x" << std::hex << region->getMemOffset()
            << " ends at 0x" << end;
  static int counter = 0;
  static int unnamed = 0;

  for (int j = 0; j < region->getDiskSize(); j += 1, ++offset) {
    CHECK(region->getMemOffset() + j == region->getDiskOffset() + j)
        << "Memory offset != Disk offset, investigate!";

    if (*offset == 0) {
      continue;
    }
    LOG(INFO) << "Nonzero at 0x" << std::hex << region->getMemOffset() + j;
    uint64_t size = j;
    while (*offset != 0) {
      ++j;
      ++offset;
      if (region->getMemOffset() + j == end) {
        LOG(INFO) << "Hit end of region";
        break;
      }
    }

    uint64_t off = size % 4;
    auto diff = j - size;
    if (diff + off <= 4) {
      diff += off;
    }
    //TODO(lukas): -fPIC & -pie ?
    if (diff <= 4 && diff  >= 3) {

      auto tmp_ptr = reinterpret_cast<std::uint64_t *>(static_cast<uint8_t *>(
            region->getPtrToRawData()) + size - off);
      if (handleDataXref(segment, region->getMemOffset() + size - off, *tmp_ptr)) {
        LOG(INFO) << "Fished up " << std::hex
                  << region->getMemOffset() + size << " " << *tmp_ptr;
        continue;
      }

      if (gSectionManager->IsInRegion(region, *tmp_ptr)) {
        std::string name = base_name + "_unnamed_" + std::to_string(++unnamed);
        WriteDataXref({region->getMemOffset() + size - off,
                      *tmp_ptr,
                      segment},
                      name);

        //Now add target as var
        auto cfg_var = segment->add_vars();
        cfg_var->set_name(name);
        cfg_var->set_ea(*tmp_ptr);
        gDisassContext->segment_vars.insert({*tmp_ptr, cfg_var});
        continue;

      } else if (gSectionManager->IsInBinary(*tmp_ptr)) {
        LOG(INFO) << "Cross xref " << std::hex
                  << region->getMemOffset() + size - off << " " << *tmp_ptr;
        cross_xrefs.push_back({region->getMemOffset() + size - off,
                              *tmp_ptr,
                              segment});
        continue;
      }
    }
    std::string name = base_name + "_" + std::to_string(counter);
    ++counter;
    LOG(INFO) << "\tAdding var " << name << " at 0x" << std::hex << region->getMemOffset() + size;
    auto var = segment->add_vars();
    var->set_ea(region->getMemOffset() + size);
    var->set_name(name);
    gDisassContext->segment_vars.insert({region->getMemOffset() + size, var});
  }
}

void CFGWriter::xrefsInSegment(SymtabAPI::Region *region,
                               mcsema::Segment *segment) {

  // Both are using something smarter, as they may contain other
  // data as static strings
  if (region->getRegionName() == ".data" ||
      region->getRegionName() == ".rodata") {
    return;
  }
  auto offset = static_cast<std::uint64_t*>(region->getPtrToRawData());

  for (int j = 0; j < region->getDiskSize(); j += 8, offset++) {
    // Just so we know, there was something shady
    LOG(INFO)
      << std::hex << "Trying to resolve xref from " << region->getRegionName()
      << " at 0x" <<region->getMemOffset() + j << " targeting 0x" << *offset;

    if (!handleDataXref(segment, region->getMemOffset() + j, *offset)) {
      LOG(INFO) << "\tDid not resolve it, try to search in .text";

      if (gSectionManager->IsInRegion(".text", *offset)) {
        LOG(INFO) << "\tXref is pointing into .text";
        code_xrefs_to_resolve.insert(
            {*offset,{region->getMemOffset() + j, *offset, segment}});
      }
    }
  }
}

void writeRawData(std::string& data, SymtabAPI::Region* region) {
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
  LOG(INFO) << "Writing raw " << number << " to offset " << offset;
  if (offset < 0) {
    LOG(FATAL) << "Trying yo write raw on negative offset";
  }
  if (offset + 3 >= data.size()) {
    LOG(WARNING) << "AsRaw would overwrite stuff";
    data.resize(offset + 3, '\0');
  }
  for (int i = 0; i < 4; ++i) {
    data[offset + i] = (number >> (i * 8));
  }
}

//TODO(lukas): Relic of old PR, not sure if needed
//             -fPIC & -pie?
void CFGWriter::writeGOT(SymtabAPI::Region* region,
                                 mcsema::Segment* segment) {
  auto rela_dyn = gSectionManager->GetRegion(".rela.dyn");
  if (!rela_dyn || !FLAGS_pie_mode) {
    return;
  }
  const auto &relocations = rela_dyn->getRelocations();

  auto old_data = segment->mutable_data();
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
        auto cfg_xref = segment->add_xrefs();
        cfg_xref->set_target_name(ext_var->name());
        cfg_xref->set_ea(reloc.rel_addr());
        cfg_xref->set_target_ea(ext_var->ea());
        cfg_xref->set_target_is_code(false);
        cfg_xref->set_target_fixup_kind(mcsema::DataReference::Absolute);
        cfg_xref->set_width(ptr_byte_size);
        found = true;
        gDisassContext->data_xrefs.insert({reloc.rel_addr(), cfg_xref});
        WriteAsRaw(data, ext_var->ea(), reloc.rel_addr() - segment->ea());
      }
    }
    if (!found && !reloc.name().empty()) {
      LOG(WARNING)
          << "Giving magic_space to" << reloc.name();

      auto unreal_ea = magic_section.AllocSpace(ptr_byte_size);
      auto cfg_xref = segment->add_xrefs();
      cfg_xref->set_target_name(reloc.name());
      cfg_xref->set_ea(reloc.rel_addr());
      cfg_xref->set_target_ea(unreal_ea);
      cfg_xref->set_target_is_code(true);
      cfg_xref->set_target_fixup_kind(mcsema::DataReference::Absolute);
      cfg_xref->set_width(ptr_byte_size);
      gDisassContext->data_xrefs.insert({reloc.rel_addr(), cfg_xref});
      WriteAsRaw(data, unreal_ea, reloc.rel_addr() - segment->ea());

    if (gExt_func_manager->IsExternal(reloc.name())) {
        auto func = gExt_func_manager->GetExternalFunction(reloc.name());
        func.imag_ea = unreal_ea;
        func.WriteHelper(module, unreal_ea);
      }
    }
  }
  for (int i = 0; i < data.size(); ++i) {
    LOG(INFO) << std::hex << +static_cast<uint8_t>((data)[i]);
  }
  segment->set_data(data);
}

void CFGWriter::writeRelocations(SymtabAPI::Region* region,
                         mcsema::Segment *segment) {

  auto rela_dyn = gSectionManager->GetRegion(".rela.plt");
  if (!rela_dyn || !FLAGS_pie_mode) {
    return;
  }
  const auto &relocations = rela_dyn->getRelocations();
  auto data = segment->mutable_data();

  for (auto reloc : relocations) {
    bool found = false;
    LOG(INFO) << "Trying to resolve reloc " << reloc.name();
    for (auto ext_func : magic_section.ext_funcs) {
      if (reloc.name() == ext_func->name()) {
        LOG(INFO) << "Writing xref in got 0x" << std::hex
                  << reloc.rel_addr() << " -> 0x" << ext_func->ea();
        auto xref = segment->add_xrefs();
        xref->set_target_name(ext_func->name());
        xref->set_ea(reloc.rel_addr());
        xref->set_target_ea(ext_func->ea());
        xref->set_target_is_code(true);
        xref->set_target_fixup_kind(mcsema::DataReference::Absolute);
        xref->set_width(ptr_byte_size);
        found = true;
        WriteAsRaw(*data, ext_func->ea(), reloc.rel_addr() - segment->ea());
      }
    }
  }
}

void CFGWriter::ResolveCrossXrefs() {
  for (auto &xref : cross_xrefs) {
    auto g_var = gDisassContext->global_vars.find(xref.target_ea);
    if (g_var != gDisassContext->global_vars.end()) {
      LOG(ERROR)
          << "CrossXref is targeting global variable and was not resolved earlier!";
      continue;
    }

    if(!handleDataXref(xref)) {
      LOG(INFO) << std::hex << xref.ea << " is unresolved, targeting "
                << xref.target_ea;
      if (gSectionManager->IsInRegions({".data", ".rodata", ".bss"}, xref.target_ea)) {
        LOG(INFO) << "It is pointing into data sections, assuming it is xref";
        WriteDataXref(xref);
      }
    }
    // If it's xref into .text it's highly possible it is
    // entrypoint of some function that was missed by speculative parse.
    // Let's try to parse it now

    if (gSectionManager->IsInRegion(".text", xref.target_ea)) {
      LOG(INFO) << "\tIs acturally targeting something in .text!";
      code_xrefs_to_resolve.insert({xref.target_ea, xref});
    }
  }
}

void writeBssXrefs(SymtabAPI::Region *region,
                   mcsema::Segment *segment,
                   const DisassContext::SymbolMap<mcsema::ExternalVariable *> &externals) {
  for (auto &external : externals) {
    if (gSectionManager->IsInRegion(region, external.first)) {
      auto cfg_xref = segment->add_xrefs();
      cfg_xref->set_ea(external.first);
      cfg_xref->set_width(8);
      cfg_xref->set_target_ea(external.first);
      cfg_xref->set_target_name(external.second->name());
      cfg_xref->set_target_is_code(false);
      cfg_xref->set_target_fixup_kind(mcsema::DataReference::Absolute);
    }
  }
}

// Write content of sections, try to parse for xrefs and vars
// .rodata, .data have special treatment, since there can be string
// variables and such
// Write things into gDisassContext
void CFGWriter::writeInternalData() {
  auto dataRegions = gSectionManager->GetDataRegions();

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

    if ( region->getRegionName() == ".fini_array" ) {
      continue;
    }
    auto cfg_internal_data = module.add_segments();

    std::string data;
    writeRawData(data, region);

    // .init & .fini should be together
    if ( region->getRegionName() == ".init_array" ) {
      SymtabAPI::Region* fini;
      symtab.findRegion( fini, ".fini_array" );
      writeRawData( data, fini );
      writeDataVariables(fini, cfg_internal_data);

      xrefsInSegment( fini, cfg_internal_data );
    }

    cfg_internal_data->set_ea(region->getMemOffset());
    cfg_internal_data->set_data(data);
    cfg_internal_data->set_read_only(region->getRegionPermissions() ==
                                   SymtabAPI::Region::RP_R);
    cfg_internal_data->set_is_external(false);
    cfg_internal_data->set_name(region->getRegionName());
    cfg_internal_data->set_is_exported(false);      /* TODO: As for now, ignored */
    cfg_internal_data->set_is_thread_local(false); /* TODO: As for now, ignored */

    // TODO(lukas): We probably don't need to parse these?
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
      ".gcc_except_table",
      ".jcr",
    };
    if (dont_parse.find(region->getRegionName()) == dont_parse.end()) {
      writeDataVariables(region, cfg_internal_data);

      xrefsInSegment( region, cfg_internal_data );
    }

    // IDA output of .bss produced some "self xrefs"
    if (region->getRegionName() == ".bss") {
      writeBssXrefs(region, cfg_internal_data, gDisassContext->external_vars);
    }

    // Apply relocations of external functions
    if (region->getRegionName() == ".got.plt") {
      writeRelocations(region, cfg_internal_data);
    }

    // Apply relocations of external variables if needed
    if (region->getRegionName() == ".got") {
      writeGOT(region, cfg_internal_data);
    }
  }
  ResolveCrossXrefs();
}

void CFGWriter::writeDataVariables(Dyninst::SymtabAPI::Region *region,
                                   mcsema::Segment *segment) {
  std::vector<SymtabAPI::Symbol *> vars;
  symtab.getAllSymbolsByType(vars, SymtabAPI::Symbol::ST_OBJECT);

  for (auto &a : vars) {
    if ((a->getRegion() && a->getRegion() == region) ||
        (a->getOffset() == region->getMemOffset())) {

      if (gDisassContext->external_vars.find(a->getOffset()) !=
          gDisassContext->external_vars.end()) {
        continue;
      }

      auto var = segment->add_vars();
      var->set_ea(a->getOffset());
      var->set_name(a->getMangledName());

      gDisassContext->segment_vars.insert({a->getOffset(), var});
    }
  }
  if (region->getRegionName() == ".rodata" ||
      region->getRegionName() == ".data") {
    LOG(INFO) << "Speculative parse of " << region->getRegionName();
    tryParseVariables(region, segment);
  }
}


bool CFGWriter::isExternal(Address addr) const {
/*  bool is = false;
  if (code_object.cs()->linkage().find(addr) != code_object.cs()->linkage().end()) {
    is = gExt_func_manager->IsExternal(code_object.cs()->linkage()[addr]);
  }

  if (gDisassContext->external_vars.find(addr) != gDisassContext->external_vars.end()) {
    is  = true;
  }

  return is;
*/
  return gDisassContext->external_vars.find(addr) != gDisassContext->external_vars.end() ||
         gDisassContext->external_funcs.find(addr) != gDisassContext->external_funcs.end();
}

std::string CFGWriter::getExternalName(Address addr) const {
  auto name_hndl = code_object.cs()->linkage().find(addr);
  if (name_hndl != code_object.cs()->linkage().end()) {
    return name_hndl->second;
  }
  return "";
}
