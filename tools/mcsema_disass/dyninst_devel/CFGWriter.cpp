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

bool SmarterTryEval(InstructionAPI::Expression *expr,
                        const Address ip,
                        Address &result,
                        Address instruction_size=0) {
  /*InstructionAPI::RegisterAST rip =
      InstructionAPI::RegisterAST::makePC(Dyninst::Arch_x86_64);
  auto ip_value = InstructionAPI::Result(InstructionAPI::u64, ip);
  expr->bind(&rip, ip_value);
*/
  LOG(INFO) << expr->format();
  /*auto res = expr->eval();
  if (expr->eval().format() != "[empty]") {
    LOG(INFO) << "Returned smart";
    result = expr->eval().convert<Address>();
    return true;
  }*/
  if (auto bin = dynamic_cast<InstructionAPI::BinaryFunction *>(expr)) {
    LOG(INFO) << "BF";
    std::vector<InstructionAPI::InstructionAST::Ptr> args;
    bin->getChildren(args);

    Address left, right;

    auto first = SmarterTryEval(
        dynamic_cast<InstructionAPI::Expression *>(args[0].get()),
        ip, left, instruction_size);
    auto second = SmarterTryEval(
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
    LOG(INFO) << "IMM";
    result = imm->eval().convert<Address>();
    return true;
  } else if (auto deref = dynamic_cast<InstructionAPI::Dereference *>(expr)) {
    LOG(INFO) << "DEREF";
    std::vector<InstructionAPI::InstructionAST::Ptr> args;
    deref->getChildren(args);
    return SmarterTryEval(dynamic_cast<InstructionAPI::Expression *>(args[0].get()),
                   ip + instruction_size,
                   result);
  } else if (auto reg = dynamic_cast<InstructionAPI::RegisterAST *>(expr)) {
    if (reg->format() == "RIP") {
      LOG(INFO) << "RIP " << ip << " + " << instruction_size;
      result = ip;
      return true;
    }
  }
  return false;
}

Address TryRetrieveAddrFromStart(ParseAPI::CodeObject &code_object,
                                 Address start,
                                 size_t index) {
  for (auto func : code_object.funcs()) {
    if (func->addr() == start) {

      auto entry_block = func->entry();
      LOG(INFO) << "Start 0x" << std::hex << start
                << " end 0x" << entry_block->end();

      using Insn = std::map<Offset, InstructionAPI::Instruction::Ptr>;
      Insn instructions;
      entry_block->getInsns(instructions);
      //TODO(lukas): rename
      auto callq = std::prev(instructions.end(), 2 + index);

      LOG(INFO) << "Current rip 0x" << std::hex << callq->first;

      auto second_operand = callq->second.get()->getOperand(1);
      LOG(INFO) << second_operand.format(Arch_x86_64);

      Address offset = 0;
      //lea
      auto rip = callq->first;
      if (callq->second->getOperation().getID() == 268) {
        rip += callq->second->size();
      }
      if (!SmarterTryEval(second_operand.getValue().get(), rip, offset, callq->second->size())) {
        LOG(FATAL) << "Could not eval basic start addresses!";
      }
      code_object.parse(offset, true);
      LOG(INFO) << "Retrieving info from _start at index " << index
                << " got addr 0x" << std::hex << offset << std::dec;
      return offset;
      //}
    }
  }
  LOG(FATAL) << "Was not able to retrieve info from _start at index "
             << index;
}

bool IsInRegion(SymtabAPI::Region *r, Address a) {
  if (a < r->getMemOffset()) {
    return false;
  }
  if (a > (r->getMemOffset() + r->getMemSize())) {
    return false;
  }
  return true;
}

bool IsInRegions(const std::vector<SymtabAPI::Region *> &regions, Address a) {
  for (auto &r : regions) {
    if (IsInRegion(r, a)) {
      return true;
    }
  }
  return false;
}

void WriteDataXref(const CFGWriter::CrossXref<mcsema::Segment> &xref,
                   const std::string &name="",
                   bool is_code=false,
                   uint64_t width=8) {
  LOG(INFO) << "\tWriting xref targeting 0x" << std::hex << xref.target_ea;
  auto cfg_xref = xref.segment->add_xrefs();
  cfg_xref->set_ea(xref.ea);
  cfg_xref->set_width(width);
  cfg_xref->set_target_ea(xref.target_ea);
  cfg_xref->set_target_name(name);
  cfg_xref->set_target_is_code(is_code);
  cfg_xref->set_target_fixup_kind(mcsema::DataReference::Absolute);
}

bool FishForXref(SymbolMap vars,
                 const CFGWriter::CrossXref<mcsema::Segment> &xref,
                 bool is_code=false, uint64_t width=8) {
  auto var = vars.find(xref.target_ea);
  if (var != vars.end()) {
    WriteDataXref(xref, var->second, is_code, width);
    return true;
  }
  return false;
}

//TODO(lukas): Investigate, this ignores .bss?
bool IsInBinary(ParseAPI::CodeSource &code_source, Address a) {
  for (auto &r : code_source.regions()) {
    if (r->contains(a)) {
      return true;
    }
  }
  LOG(INFO) << std::hex << a << std::dec << " is not contained in code_source";
  return false;
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
      magic_section(gDisassContext->magic_section) {

  // Populate skip_funcss with some functions known to cause problems
  skip_funcss = {
                 "_fini",
                 "__libc_start_main"
                 };

  // Populate func_map

  std::vector<SymtabAPI::Function *> functions;
  symtab.getAllFunctions(functions);
  bool is_stripped = symtab.isStripped();
  LOG(INFO) << "Binary is stripped: " << is_stripped;

  std::vector<SymtabAPI::Region *> regions;
  symtab.getAllRegions(regions);

  for (auto reg : regions) {
      gSection_manager->AddRegion(reg);
  }


  // We need to get main! Heuristic for stripped binaries is that main is
  // passed to __libc_start_main as last argument from _start, which we can
  // find, because it is entrypoint
  entry_point = symtab.getEntryOffset();
  code_object.parse(entry_point, true);
  Address main_offset = TryRetrieveAddrFromStart(code_object, entry_point, 0);
  Address ctor_offset = TryRetrieveAddrFromStart(code_object, entry_point, 1);
  Address dtor_offset = TryRetrieveAddrFromStart(code_object, entry_point, 2);

  // TODO(lukas): Check if there's a better way

  CHECK(main_offset) << "Entrypoint with name "
                     << FLAGS_entrypoint
                     <<" was not found!";

  for (auto func : code_object.funcs()) {
    func_map[func->addr()] = func->name();
    LOG(INFO) << func->addr() << " " << func->name();
  }
  func_map[main_offset] = FLAGS_entrypoint;
  LOG(INFO) << "Function at " << main_offset << " is " << FLAGS_entrypoint;

  // We need to give libc ctor/dtor names
  if (symtab.isStripped()) {
    LOG(INFO) << "Renaming 0x:" << std::hex << ctor_offset << " to init";
    func_map[ctor_offset] = "init";

    LOG(INFO) << "Renaming 0x:" << std::hex << dtor_offset << " to fini";
    func_map[dtor_offset] = "fini";
  }

  for (auto reg : regions) {
    if (reg->getRegionName() == ".text") {
      //relocations = reg->getRelocations();
    }
  }

  getNoReturns();

  //TODO(lukas): Move out
  Address highest = 0;
  for (auto reg : regions) {
    highest = std::max(reg->getMemOffset() + reg->getMemSize(), highest);
  }
  highest += 0x420;
  LOG(INFO) << "Magic section starts at 0x" << std::hex << highest;
  magic_section.init(highest, ptr_byte_size);
}

void CFGWriter::write() {
  writeExternalFunctions();
  writeExternalVariables();
  LOG(INFO) << "Writing internal data";
  writeInternalData();
  writeGlobalVariables();

  writeInternalFunctions();

  //Handle new functions found via various xrefs, mostly in stripped binary
  LOG(INFO) << code_xrefs_to_resolve.size() << " code xrefs is unresolved!";
  for (auto &a : code_xrefs_to_resolve) {
    code_object.parse(a.first, true);
    WriteDataXref(a.second, "", true);
  }

  for (auto func : code_object.funcs()) {
    if (code_xrefs_to_resolve.find(func->addr()) != code_xrefs_to_resolve.end() &&
        func_map.find(func->addr()) == func_map.end()) {

      func_map[func->addr()] = func->name();
      auto cfgInternalFunc = module.add_funcs();

      ParseAPI::Block *entryBlock = func->entry();
      cfgInternalFunc->set_ea(entryBlock->start());

      cfgInternalFunc->set_is_entrypoint(func);

      for (ParseAPI::Block *block : func->blocks()) {
        writeBlock(block, func, cfgInternalFunc);
      }

      cfgInternalFunc->set_name(func_map[func->addr()]);
      LOG(INFO) << "Added " << func->name() << " into module, found via xref";
    }
  }

  while (!inst_xrefs_to_resolve.empty()) {
    LOG(WARNING) << inst_xrefs_to_resolve.size() << " inst code xrefs is unresolved!";
    for (auto &a : inst_xrefs_to_resolve) {
      code_object.parse(a.first, false);
    }

    auto old_set = inst_xrefs_to_resolve;
    inst_xrefs_to_resolve.clear();
    for (auto func : code_object.funcs()) {
      if (old_set.find(func->addr()) != old_set.end() &&
          func_map.find(func->addr()) == func_map.end()) {

        func_map[func->addr()] = func->name();
        auto cfgInternalFunc = module.add_funcs();

        ParseAPI::Block *entryBlock = func->entry();
        cfgInternalFunc->set_ea(entryBlock->start());

        cfgInternalFunc->set_is_entrypoint(func);

        for (ParseAPI::Block *block : func->blocks()) {
          writeBlock(block, func, cfgInternalFunc);
        }

        cfgInternalFunc->set_name(func_map[func->addr()]);
        LOG(INFO) << "Added " << func->name() << " into module, found via xref";
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
      // Most likely relocation. So as IDA we can also make up some addr
      if (!s->getOffset() && !s->getSize()) {
        LOG(WARNING)
            << "External var has no ea! " << s->getMangledName();
        LOG(WARNING)
            << "External var has no size! " << s->getMangledName();

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
        external_var->set_size(8);
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

bool CFGWriter::shouldSkipFunction(const std::string &name) const {
  return skip_funcss.find(name) != skip_funcss.end();
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
    if (shouldSkipFunction(func->name()))
      continue;
    else if (isExternal(func->entry()->start()))
      continue;
    // We want to ignore the .got.plt stubs, since they are not needed
    // and cfg file would grow significantly
    else if (IsInRegion(gSection_manager->getRegion(".got.plt"),
                        func->entry()->start())) {
      continue;
    }

    auto cfgInternalFunc = module.add_funcs();

    ParseAPI::Block *entryBlock = func->entry();
    cfgInternalFunc->set_ea(entryBlock->start());

    cfgInternalFunc->set_is_entrypoint(
        notEntryPoints.find(func->name()) == notEntryPoints.end());

    for (ParseAPI::Block *block : func->blocks()) {
      writeBlock(block, func, cfgInternalFunc);
    }

    if (func_map.find(func->addr()) != func_map.end()) {
      cfgInternalFunc->set_name(func_map[func->addr()]);
    }
  }
}


//TODO(lukas): This one is basically unchanged from original PR.
void CFGWriter::writeBlock(ParseAPI::Block *block, ParseAPI::Function *func,
                           mcsema::Function *cfgInternalFunc) {

  mcsema::Block *cfgBlock = cfgInternalFunc->add_blocks();
  cfgBlock->set_ea(block->start());

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
      cfgBlock->add_successor_eas(edge->trg()->start());
  }

  // Write instructions

  std::map<Offset, InstructionAPI::Instruction::Ptr> instructions;
  block->getInsns(instructions);

  Address ip = block->start();

  for (auto p : instructions) {
    InstructionAPI::Instruction *instruction = p.second.get();

    writeInstruction(instruction, ip, cfgBlock);
    ip += instruction->size();
  }

}

void CFGWriter::writeInstruction(InstructionAPI::Instruction *instruction,
                                 Address addr, mcsema::Block *cfgBlock) {

  mcsema::Instruction *cfgInstruction = cfgBlock->add_instructions();

  std::string instBytes;
  for (int offset = 0; offset < instruction->size(); ++offset) {
    instBytes += (int)instruction->rawByte(offset);
  }

  cfgInstruction->set_bytes(instBytes);
  cfgInstruction->set_ea(addr);

  std::vector<InstructionAPI::Operand> operands;
  instruction->getOperands(operands);

  if (instruction->getCategory() == InstructionAPI::c_CallInsn) {
    handleCallInstruction(instruction, addr, cfgInstruction);
  } else {
    handleNonCallInstruction(instruction, addr, cfgInstruction);
  }
  //TODO(lukas): We just found it, no need to bother with it?
  //             But what if it needs to be start of function?
  code_xrefs_to_resolve.erase(addr);
}


void writeDisplacement(mcsema::Instruction *cfgInstruction, Address &address,
        const std::string& name = "") {
  // Addres is uint64_t and in CFG ea is int64_t
  if (static_cast<int64_t>(address) <= 0) {
    return;
  }

  AddCodeXref( cfgInstruction, CodeReference::DataTarget,
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

void CFGWriter::checkDisplacement(Dyninst::InstructionAPI::Expression *expr,
                       mcsema::Instruction *cfgInstruction) {

  //TODO(lukas): This is possibly incorrect attempt to cull down amount of
  //             "false" xrefs of type MemoryDisplacement
  if (cfgInstruction->xrefs_size()) {
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
          writeDisplacement(cfgInstruction, displacement);
        }
      }
    }
  } else {
    if (auto displacement = DisplacementHelper(expr)) {
      writeDisplacement(cfgInstruction, displacement);
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
  auto func = func_map.find(addr);
  if (func != func_map.end()) {
    return func->second;
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
                                      mcsema::Instruction *cfgInstruction) {
  Address target;
  std::vector<InstructionAPI::Operand> operands;
  instruction->getOperands(operands);

  Address size = instruction->size();

  LOG(INFO) << "TryEval " << addr << " " << size;
  bool got_result = false;
  if (SmarterTryEval(operands[0].getValue().get(), addr, target, size)) {
    handleXref(cfgInstruction, target);
    // What can happen is that we get xref somewhere in the .text and handleXref
    // fills it with defaults. We need to check and correct it if needed
    if (IsInRegion(gSection_manager->getRegion(".text"), target)) {
      auto xref = cfgInstruction->mutable_xrefs(0);
      //xref->set_target_type(CodeReference::CodeTarget);
      xref->set_operand_type(CodeReference::ControlFlowOperand);

      // It is pointing in .text and not to a function?
      // That's weird, quite possibly we are missing a function!
      if (func_map.find(target) == func_map.end()) {
        LOG(INFO) << "Unresolved inst_xref " << target;
        inst_xrefs_to_resolve.insert(
          {target , {addr, target, cfgInstruction}});
      }
    }

    if (isNoReturn(getExternalName(target))) {
      cfgInstruction->set_local_noreturn(true);
    }
    return;
  }


  // Below is territory still occupied by old PR and I am not sure what to do
  // with it.
  // It didn't work without it, but it does now, magic?
  // Keeping it to see how relocs were used
  LOG(INFO) << "CallInst fallback to default " << addr;
/*
  if (relocations.size() > 0) {
    auto entry = *(relocations.begin());
    bool found = false;

    for (auto ent : relocations) {
      if (ent.rel_addr() == (addr + size + 1)) {
        entry = ent;
        found = true;
        break;
      }
    }

    if (!((!found) || (found && !entry.getDynSym()->getRegion()))) {
        Offset off = entry.getDynSym()->getOffset();

        AddCodeXref(cfgInstruction,
                    CodeReference::CodeTarget,
                    CodeReference::ControlFlowOperand,
                    CodeReference::Internal,
                    off);
      return;
    }
  }
*/
  // TODO: This is when things like callq %*rcx happen, not sure yet how to deal
  // with it correctly, this seems to work good enough for now

  auto name = getXrefName(target);
  if (name == "__mcsema_unknown") {
    name = "";
  }
  AddCodeXref(cfgInstruction,
              CodeReference::CodeTarget,
              CodeReference::ControlFlowOperand,
              CodeReference::Internal,
              target, name);
}

Address CFGWriter::immediateNonCall( InstructionAPI::Immediate* imm,
        Address addr, mcsema::Instruction* cfgInstruction ) {

  Address a = imm->eval().convert<Address>();
  auto allSymsAtOffset = symtab.findSymbolByOffset(a);
  bool isRef = false;

  if (allSymsAtOffset.size() > 0) {
    for (auto symbol : allSymsAtOffset) {
      if (symbol->getType() == SymtabAPI::Symbol::ST_OBJECT) {
        isRef = true;
      }
    }
  }

  // TODO(lukas): This is ugly hack from previous PR, but it works for now
  // Almost certainly needs rework because of -fPIC and -pie
  if (a > 0x10000) {
    isRef = true;
  }
  if (a > 0xffffffffffffff00) {
    isRef = false;
  }

  if (isRef) {
    auto cfgCodeRef = AddCodeXref(cfgInstruction,
                                CodeReference::DataTarget,
                                CodeReference::ImmediateOperand,
                                CodeReference::Internal,
                                a, getXrefName(a));

    if (isExternal(a) ||
        gDisassContext->external_vars.find(a) != gDisassContext->external_vars.end()) {
        cfgCodeRef->set_location(CodeReference::External);
    }
    //if (handleXref(cfgInstruction, a, true)) {
    //  auto xref = cfgInstruction->mutable_xrefs(cfgInstruction->xrefs_size() - 1);
    //  xref->set_operand_type(CodeReference::ImmediateOperand);
      if (getXrefName(a) == "__mcsema_unknown" &&
          IsInRegion(gSection_manager->getRegion(".text"), a)) {
        LOG(INFO) << std::hex
                  << "IMM may be working with new function starting at" << a;
        inst_xrefs_to_resolve.insert({a, {}});
      }
      return a;
    }
  //}
  return 0;
}

Address CFGWriter::dereferenceNonCall(InstructionAPI::Dereference* deref,
                                   Address addr,
                                   mcsema::Instruction* cfgInstruction) {

  std::vector<InstructionAPI::InstructionAST::Ptr> children;
  deref->getChildren(children);
  auto expr = dynamic_cast<InstructionAPI::Expression *>(children[0].get());

  CHECK(expr) << "Expected expression";

  Address a;
  if (SmarterTryEval(expr, addr, a)) {
    //TODO(lukas): Possibly wrong with -pie & -fPIC?
    /*if (a > 0xffffffffffffff00) {
      return 0;
    }*/

    auto cfgCodeRef = AddCodeXref(cfgInstruction,
                                  CodeReference::DataTarget,
                                  CodeReference::MemoryOperand,
                                  CodeReference::Internal, a,
                                  getXrefName(a));
    if (isExternal(a) || gDisassContext->external_vars.find(a) != gDisassContext->external_vars.end()) {
      cfgCodeRef->set_location(CodeReference::External);
    }
    return a;
  }

  return 0;
}


bool CFGWriter::handleXref(mcsema::Instruction *cfg_instruction,
                           Address addr,
                           bool force) {
  LOG(INFO) << "HandleXref to " << addr;
  if (auto func = magic_section.GetExternalFunction(addr)) {
    LOG(INFO) << "Code xref to func in magic_section at " << addr;
    auto code_ref = AddCodeXref(cfg_instruction,
                                CodeReference::DataTarget,
                                CodeReference::ControlFlowOperand,
                                CodeReference::External,
                                func->ea(),
                                func->name());
    return true;
  }

  auto func = func_map.find(addr);
  if (func != func_map.end()) {
    LOG(INFO) << "Code xref to func at " << addr;
    auto code_ref = AddCodeXref(cfg_instruction,
                                  CodeReference::CodeTarget,
                                  CodeReference::ControlFlowOperand,
                                  CodeReference::Internal, addr,
                                  func->second);
    if (isExternal(addr)) {
      code_ref->set_location(CodeReference::External);
    }
    return true;
  }

  auto g_var = gDisassContext->global_vars.find(addr);
  if (g_var != gDisassContext->global_vars.end()) {
    auto code_ref = AddCodeXref(cfg_instruction,
                                  CodeReference::DataTarget,
                                  CodeReference::MemoryOperand,
                                  CodeReference::Internal, addr,
                                  g_var->second->name());
    return true;
  }

  auto s_var = gDisassContext->segment_vars.find(addr);
  if (s_var != gDisassContext->segment_vars.end()) {
    auto code_ref = AddCodeXref(cfg_instruction,
                                  CodeReference::DataTarget,
                                  CodeReference::MemoryOperand,
                                  CodeReference::Internal, addr,
                                  s_var->second->name());
    return true;
  }

  auto ext_var = gDisassContext->external_vars.find(addr);
  if (ext_var != gDisassContext->external_vars.end()) {
    LOG(INFO) << "Code xref to ext_var at " << addr;
    auto code_ref = AddCodeXref(cfg_instruction,
                                  CodeReference::DataTarget,
                                  CodeReference::MemoryOperand,
                                  CodeReference::External, addr,
                                  ext_var->second->name());
    return true;
  }
  auto ext_func = gDisassContext->external_funcs.find(addr);
  if (ext_func != gDisassContext->external_funcs.end()) {
    LOG(INFO) << "Code xref to ext_func at " << addr;
    auto code_ref = AddCodeXref(cfg_instruction,
                                  CodeReference::DataTarget,
                                  CodeReference::ControlFlowOperand,
                                  CodeReference::External,
                                  magic_section.GetAllocated(addr),
                                  ext_func->second->name());
    return true;
  }
  if (force) {
    LOG(INFO) << "Could not recognize xref anywhere falling to default";
    auto code_ref = AddCodeXref(cfg_instruction,
                                  CodeReference::DataTarget,
                                  CodeReference::MemoryOperand,
                                  CodeReference::Internal, addr);
    if (isExternal(addr)) {
      code_ref->set_location(CodeReference::External);
    }
    return true;
  }
  return false;
}

void CFGWriter::handleNonCallInstruction(
    Dyninst::InstructionAPI::Instruction *instruction,
    Address addr,
    mcsema::Instruction *cfgInstruction) {

  std::vector<InstructionAPI::Operand> operands;
  instruction->getOperands(operands);

  // RIP already points to the next instruction
  addr += instruction->size();

  // Sometimes some .text address is stored somewhere in data segment.
  // That can be function pointer, so we need to check if we actually
  // have that function parsed
  Address direct_values[2] = {0, 0};
  auto i = 0U;
  LOG(INFO) << instruction->format() << " at 0x" << std::hex << addr - instruction->size();
  for (auto op : operands) {
    auto expr = op.getValue();
    LOG(INFO) << expr->format();
    if (auto imm = dynamic_cast<InstructionAPI::Immediate *>(expr.get())) {
      LOG(INFO) << "Dealing with Immidiate as op at 0x" << std::hex << addr - instruction->size();
      direct_values[i] = immediateNonCall( imm, addr, cfgInstruction);
    } else if (
        auto deref = dynamic_cast<InstructionAPI::Dereference *>(expr.get())) {
      LOG(INFO) << "Dealing with Dereference as op at 0x" << std::hex << addr - instruction->size();
      direct_values[i] = dereferenceNonCall( deref, addr, cfgInstruction);
    } else if (
        auto bf = dynamic_cast<InstructionAPI::BinaryFunction *>(expr.get())) {
      LOG(INFO) << "Dealing with BinaryFunction as op at 0x" << std::hex << addr - instruction->size();

      // 268 stands for lea
      // 8 stands for jump
      auto instruction_id = instruction->getOperation().getID();
      if (instruction_id == 268) {
        Address a;
        /*if (addr - instruction->size() == 0x405c7d) {
          auto xref = AddCodeXref(cfgInstruction,
                                  CodeReference::DataTarget,
                                  CodeReference::MemoryDisplacementOperand,
                                  CodeReference::Internal, 6618560);
        }*/
        //addr -= instruction->size();
        if(SmarterTryEval(expr.get(), addr, a)) {
          handleXref(cfgInstruction, a);
          if (IsInRegion(gSection_manager->getRegion(".text"), a)) {
            // get last one and change it to code
            auto xref = cfgInstruction->mutable_xrefs(cfgInstruction->xrefs_size() - 1);
            xref->set_operand_type(CodeReference::MemoryOperand);
          }
          direct_values[i] = a;
        }
      //} else if (instruction_id == 8) {
      } else if (instruction->getCategory() == InstructionAPI::c_BranchInsn) {
        Address a;
        if (SmarterTryEval(expr.get(), addr - instruction->size(), a)) {
          auto code_ref = AddCodeXref(cfgInstruction,
                                      CodeReference::CodeTarget,
                                      CodeReference::ControlFlowOperand,
                                      CodeReference::Internal, a);
          //handleXref(cfgInstruction, a);
          if (isExternal(a)) {
            code_ref->set_location(CodeReference::External);
            code_ref->set_name(getXrefName(a));
          }
          direct_values[i] = a;
        }
      }
    } else {
      /*if (FLAGS_pie_mode &&
          instruction->getCategory() == InstructionAPI::c_BranchInsn) {
        //if (operands.size() == 1 ) {
          //EXPERIMENTAL(lukas): things like jmpq *%rdx need Offset table xref
          auto xref = cfgInstruction->add_xrefs();
          xref->set_target_type(CodeReference::DataTarget);
          xref->set_operand_type(CodeReference::OffsetTable);
          xref->set_location(CodeReference::Internal);
          xref->set_ea(4100);
        }*/
      //}
    }
    ++i;
    checkDisplacement(expr.get(), cfgInstruction);
  }
  if (direct_values[0] && direct_values[1]) {
    addr -= instruction->size();
    bool is_somewhere_reasonable = IsInRegions(
        {
          gSection_manager->getRegion(".bss"),
          gSection_manager->getRegion(".data"),
          gSection_manager->getRegion(".rodata"),
        },
        direct_values[0]);
    if (IsInRegion(gSection_manager->getRegion(".text"), direct_values[1]) &&
        is_somewhere_reasonable) {
      LOG(INFO) << "Storing address from .text into .bss";
      if (func_map.find(direct_values[0]) == func_map.end()) {
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
  LOG(INFO) << "Found " << unknown.size()
            << "possibly unknown external functions";

  for (auto &name : unknown) {
    known.push_back({name});
    LOG(INFO) << "Possibly unknown external " << name;
  }

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

    CHECK(found) << "Unresolved external function call";

    func.ea = a;
    auto cfg_external_func = magic_section.WriteExternalFunction(module, func);
    gDisassContext->external_funcs.insert({a, cfg_external_func});
    /*auto cfgExtFunc = module.add_external_funcs();

    cfgExtFunc->set_name(func.symbol_name);
    cfgExtFunc->set_ea(a);
    cfgExtFunc->set_cc(func.CfgCallingConvention());
    cfgExtFunc->set_has_return(func.has_return);
    cfgExtFunc->set_no_return(!func.has_return);
    cfgExtFunc->set_argument_count(func.arg_count);
    cfgExtFunc->set_is_weak(func.is_weak);
    */
  }
}

bool CFGWriter::handleDataXref(const CFGWriter::CrossXref<mcsema::Segment> &xref) {
  return handleDataXref(xref.segment, xref.ea, xref.target_ea);
}

bool CFGWriter::handleDataXref(mcsema::Segment *segment,
                               Address ea,
                               Address target) {
  CrossXref<mcsema::Segment> xref = {ea, target, segment};
  ContextCrossXref<mcsema::Segment *> context_xref = {ea, target, segment};
  /*if (FishForXref(gDisassContext->segment_vars ,xref)) {
    found_xref.insert(ea);
    return true;
  }*/
  // segment_vars, external_vars, global_vars
  if (gDisassContext->HandleDataXref(context_xref)) {
    found_xref.insert(ea);
    return true;
  }

  if (FishForXref(func_map, xref, true)) {
    found_xref.insert(ea);
    return true;
  }

  /*if (FishForXref(gDisassContext->external_vars, xref)) {
    found_xref.insert(ea);
    return true;
  }*/

  /* if (FishForXref(gDisassContext->global_vars, xref)) {
    found_xref.insert(ea);
    return true;
  }*/
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

      if (IsInRegion(region, *tmp_ptr)) {
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
        found_xref.insert(region->getMemOffset() + size - off);
        continue;

      } else if (IsInBinary(code_source, *tmp_ptr)) {
        LOG(INFO) << "Cross xref " << std::hex
                  << region->getMemOffset() + size - off << " " << *tmp_ptr;
        cross_xrefs.push_back({region->getMemOffset() + size - off,
                              *tmp_ptr,
                              segment});
        continue;
      } else if (IsInRegion(gSection_manager->getRegion(".bss"), *tmp_ptr)) {
        LOG(INFO) << "Xref into bss " << std::hex
                  << region->getMemOffset() + size - off << " " << *tmp_ptr;
        WriteDataXref({region->getMemOffset() + size - off,
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

//TODO(lukas): Best case remove this in favor of tryParse
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
    if (found_xref.count(region->getMemOffset() + j)) {
      LOG(WARNING) << "Dual xref detected!";
      continue;
    }
    LOG(INFO)
      << std::hex << "Trying to resolve xref from " << region->getRegionName()
      << " at 0x" <<region->getMemOffset() + j << " targeting 0x" << *offset;

    if (!handleDataXref(segment, region->getMemOffset() + j, *offset)) {
      LOG(INFO) << "Did not resolve it, try to search in .text";

      if (IsInRegion(gSection_manager->getRegion(".text"), *offset)) {
        LOG(INFO) << "Xref is pointing into .text";
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
  auto rela_dyn = gSection_manager->getRegion(".rela.dyn");
  if (!rela_dyn || !FLAGS_pie_mode) {
    return;
  }
  const auto &relocations = rela_dyn->getRelocations();

  auto old_data = segment->mutable_data();
  std::string data{*old_data};
  for (auto reloc : relocations) {
    if (!IsInRegion(region, reloc.rel_addr())) {
      continue;
    }
    bool found = false;
    LOG(INFO) << "Trying to resolve reloc " << reloc.name();
    for (auto ext_var : magic_section.ext_vars) {
      if (reloc.name() == ext_var->name()) {
        LOG(INFO) << "Xref in .got io external living in magic_section";
        auto xref = segment->add_xrefs();
        xref->set_target_name(ext_var->name());
        xref->set_ea(reloc.rel_addr());
        xref->set_target_ea(ext_var->ea());
        xref->set_target_is_code(false);
        xref->set_target_fixup_kind(mcsema::DataReference::Absolute);
        xref->set_width(ptr_byte_size);
        found = true;
        WriteAsRaw(data, ext_var->ea(), reloc.rel_addr() - segment->ea());
      }
    }
    if (!found && !reloc.name().empty()) {
      LOG(WARNING)
          << "Giving magic_space to" << reloc.name();

      auto unreal_ea = magic_section.AllocSpace(ptr_byte_size);
      auto xref = segment->add_xrefs();
      xref->set_target_name(reloc.name());
      xref->set_ea(reloc.rel_addr());
      xref->set_target_ea(unreal_ea);
      xref->set_target_is_code(true);
      xref->set_target_fixup_kind(mcsema::DataReference::Absolute);
      xref->set_width(ptr_byte_size);
      WriteAsRaw(data, unreal_ea, reloc.rel_addr() - segment->ea());

      if (reloc.name() == "__gmon_start__") {
        auto cfg_external_func = module.add_external_funcs();

        cfg_external_func->set_name(reloc.name());
        cfg_external_func->set_ea(unreal_ea);
        cfg_external_func->set_cc(mcsema::ExternalFunction::CallerCleanup);
        cfg_external_func->set_has_return(true);
        cfg_external_func->set_no_return(false);
        cfg_external_func->set_argument_count(0);
        cfg_external_func->set_is_weak(true);


      } else if (gExt_func_manager->IsExternal(reloc.name())) {
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

  auto rela_dyn = gSection_manager->getRegion(".rela.plt");
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
        LOG(INFO) << "Xref in .got io external living in magic_section";
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
    /*
    if (!found && !reloc.name().empty()) {
      LOG(WARNING)
          << "Giving magic_space to" << reloc.name();

      auto unreal_ea = magic_section.AllocSpace(ptr_byte_size);
      auto xref = segment->add_xrefs();
      xref->set_target_name(reloc.name());
      xref->set_ea(reloc.rel_addr());
      xref->set_target_ea(unreal_ea);
      xref->set_target_is_code(true);
      xref->set_target_fixup_kind(mcsema::DataReference::Absolute);
      xref->set_width(ptr_byte_size);
    }*/
  }
  /*
  auto rela_dyn = region;
  const auto &relocations = rela_dyn->getRelocations();

  for (auto reloc : relocations) {
    for (auto f : code_object.funcs()) {
      if (f->entry()->start() == reloc.getDynSym()->getOffset()) {
        handleDataXref(
            segment, reloc.rel_addr(), reloc.getDynSym()->getOffset());
        break;
      }
    }
    */
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
      LOG(WARNING) << std::hex << xref.ea << " is unresolved, targeting "
                   << xref.target_ea;
    }
    // If it's xref into .text it's highly possible it is
    // entrypoint of some function that was missed by speculative parse.
    // Let's try to parse it now

    if (IsInRegion(gSection_manager->getRegion(".text"), xref.target_ea)) {
      LOG(INFO) << "\tIs acturally targeting something in .text!";
      code_xrefs_to_resolve.insert({xref.target_ea, xref});
    }
  }
}

  void writeBssXrefs(SymtabAPI::Region *region,
                   mcsema::Segment *segment,
                   const DisassContext::SymbolMap<mcsema::ExternalVariable *> &externals) {
  for (auto &external : externals) {
    if (IsInRegion(region, external.first)) {
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

//TODO(lukas): We are writing & parsing more than is required!
//             .rodata, .data are parsed twice!
//             Use tryParse for all data sections
void CFGWriter::writeInternalData() {
  auto dataRegions = gSection_manager->GetDataRegions();

  for (auto region : dataRegions) {
    std::set<std::string> no_parse = {
      //".rela.dyn",
      //".rela.plt",
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
    auto cfgInternalData = module.add_segments();

    std::string data;
    writeRawData(data, region);

    // .init & .fini should be together
    if ( region->getRegionName() == ".init_array" ) {
      SymtabAPI::Region* fini;
      symtab.findRegion( fini, ".fini_array" );
      writeRawData( data, fini );
      writeDataVariables(fini, cfgInternalData);

      xrefsInSegment( fini, cfgInternalData );
    }

    cfgInternalData->set_ea(region->getMemOffset());
    cfgInternalData->set_data(data);
    cfgInternalData->set_read_only(region->getRegionPermissions() ==
                                   SymtabAPI::Region::RP_R);
    cfgInternalData->set_is_external(false);
    cfgInternalData->set_name(region->getRegionName());
    cfgInternalData->set_is_exported(false);      /* TODO: As for now, ignored */
    cfgInternalData->set_is_thread_local(false); /* TODO: As for now, ignored */


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
      writeDataVariables(region, cfgInternalData);

      xrefsInSegment( region, cfgInternalData );
    }

    if (region->getRegionName() == ".bss") {
      writeBssXrefs(region, cfgInternalData, gDisassContext->external_vars);
    }

    if (region->getRegionName() == ".got.plt") {
      writeRelocations(region, cfgInternalData);
    }

    if (region->getRegionName() == ".got") {
      writeGOT(region, cfgInternalData);
    }

    //TODO(lukas): Debug print, remove on release
    if (region->getRegionName() == ".rela.plt" ||
        region->getRegionName() == ".rela.dyn" ||
        region->getRegionName() == ".got") {
      LOG(INFO) << "Dumping content of: " << region->getRegionName();
      auto relocs = region->getRelocations();
      for (auto &reloc : relocs) {
        LOG(INFO) << "Entry:\n\ttarget: " << reloc.target_addr()
                  << "\n\trel: "  << reloc.rel_addr()
                  << "\n\taddend: " << reloc.addend();
      }
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

      if (gDisassContext->external_vars.find(a->getOffset()) != gDisassContext->external_vars.end()) {
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
  bool is = false;
  if (code_object.cs()->linkage().find(addr) != code_object.cs()->linkage().end()) {
    is = gExt_func_manager->IsExternal(code_object.cs()->linkage()[addr]);
  }

  if (gDisassContext->external_vars.find(addr) != gDisassContext->external_vars.end()) {
    is  = true;
  }

  return is;
}

std::string CFGWriter::getExternalName(Address addr) const {
  auto name_hndl = code_object.cs()->linkage().find(addr);
  if (name_hndl != code_object.cs()->linkage().end()) {
    return name_hndl->second;
  }
  return "";
}

// Replace in favor of smartEval
bool CFGWriter::tryEval(InstructionAPI::Expression *expr,
                        const Address ip,
                        Address &result) const {

  LOG(INFO) << expr->format();
  auto res = expr->eval();
  LOG(INFO) << "expr->eval() " << res.format();
  if (expr->eval().format() != "[empty]") {
    LOG(INFO) << "Empty";
    result = expr->eval().convert<Address>();
    return true;
  }

  if (auto bin = dynamic_cast<InstructionAPI::BinaryFunction *>(expr)) {
    LOG(INFO) << "BF";
    std::vector<InstructionAPI::InstructionAST::Ptr> args;
    bin->getChildren(args);

    Address left, right;

    auto first = tryEval(
        dynamic_cast<InstructionAPI::Expression *>(args[0].get()),
        ip, left);
    auto second = tryEval(
        dynamic_cast<InstructionAPI::Expression *>(args[1].get()),
        ip, right);
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
  } else if (auto reg = dynamic_cast<InstructionAPI::RegisterAST *>(expr)) {
    if (reg->format() == "RIP") {
      LOG(INFO) << "RIP "<< ip;
      result = ip;
      return true;
    }
  } else if (auto imm = dynamic_cast<InstructionAPI::Immediate *>(expr)) {
    result = imm->eval().convert<Address>();
    LOG(INFO) << "IMM "<< result;
    return true;
  } else if (auto deref = dynamic_cast<InstructionAPI::Dereference *>(expr)) {
    LOG(INFO) << "DER";
    std::vector<InstructionAPI::InstructionAST::Ptr> args;
    deref->getChildren(args);
    return tryEval(dynamic_cast<InstructionAPI::Expression *>(args[0].get()),
                   ip,
                   result);
  }
  LOG(INFO) << "ERR";
  return false;
}
