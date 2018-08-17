#include "CFGWriter.h"

#include <Dereference.h>
#include <Function.h>
#include <Instruction.h>
#include <InstructionAST.h>
#include <InstructionCategories.h>
#include <iostream>
#include <sstream>

#include <array>
#include <iterator>

#include <ArchSpecificFormatters.h>

#include <glog/logging.h>
#include <gflags/gflags.h>

#include "Util.h"
#include <cstdio>
DECLARE_string(entrypoint);

using namespace Dyninst;
using namespace mcsema;

namespace {
  Address TryRetrieveAddrFromStart(ParseAPI::CodeObject &code_object,
                                   Address start,
                                   size_t index) {
    for (auto func : code_object.funcs()) {
      if (func->addr() == start) {
        auto entry_block = func->entry();

        using Insn = std::map<Offset, InstructionAPI::Instruction::Ptr>;
        Insn instructions;
        entry_block->getInsns(instructions);
        auto callq = std::prev(instructions.end(), 2 + index);

        auto second_operand = callq->second.get()->getOperand(1);
        auto operand_value = dynamic_cast<InstructionAPI::Immediate *>(second_operand.getValue().get());
        Address offset = operand_value->eval().convert<Address>();
        code_object.parse(offset, true);
        LOG(INFO) << "Retrieving info from _start at index " << index
                  << " got addr 0x" << std::hex << offset << std::dec;
        return offset;
      }
    }
    LOG(FATAL) << "Was not able to retrieve info from _start at index "
               << index;
  }


} //namespace

CFGWriter::CFGWriter(mcsema::Module &m, const std::string &module_name,
                     SymtabAPI::Symtab &symtab,
                     ParseAPI::SymtabCodeSource &symCodeSrc,
                     ParseAPI::CodeObject &codeObj,
                     const ExternalFunctionManager &extFuncMgr,
                     Address entry_point)
    : module(m),
      module_name(module_name),
      symtab(symtab),
      code_source(symCodeSrc),
      code_object(codeObj),
      ext_func_manager(extFuncMgr),
      entry_point(entry_point) {

  // Populate skip_funcss with some functions known to cause problems
  skip_funcss = {
                 "_fini",
                 "__libc_start_main"
                 };

  // Populate func_map

  std::vector<SymtabAPI::Function *> functions;
  symtab.getAllFunctions(functions);
  bool is_stripped = (functions.size()) ? false : true;

  std::vector<SymtabAPI::Region *> regions;
  symtab.getAllRegions(regions);

  for (auto reg : regions) {
      section_manager.AddRegion(reg);
  }

  // We need to get main! Heuristic for stripped binaries is that main is
  // passed to __libc_start_main as last argument from _start, which we can
  // find, because it is entrypoint
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
  }
  func_map[main_offset] = FLAGS_entrypoint;

  if (is_stripped) {
    func_map[ctor_offset] = "init";
    func_map[dtor_offset] = "fini";
  }

  for (auto reg : regions) {
    if (reg->getRegionName() == ".text") {
      relocations = reg->getRelocations();
    }
  }

  getNoReturns();
}

void CFGWriter::write() {
  writeExternalFunctions();
  writeExternalVariables();
  LOG(INFO) << "Writing internal data";
  writeInternalData();
  writeGlobalVariables();

  writeInternalFunctions();

  module.set_name(module_name);
}

void CFGWriter::writeExternalVariables() {
  std::vector<SymtabAPI::Symbol *> symbols;
  symtab.getAllSymbolsByType(symbols, SymtabAPI::Symbol::ST_OBJECT);

  LOG(INFO) << "Writing " << symbols.size() << " external variables";
  for (const auto &s : symbols) {
    if (s->isInDynSymtab()) {
      external_vars.insert( { s->getOffset(), s->getMangledName() } );

      auto extVar = module.add_external_vars();
      extVar->set_name(s->getMangledName());
      extVar->set_ea(s->getOffset());
      extVar->set_size(s->getSize());
      extVar->set_is_weak(false);
      extVar->set_is_thread_local(false);
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
      auto globalVar = module.add_global_vars();
      globalVar->set_ea(a->getOffset());
      globalVar->set_name(a->getMangledName());
      globalVar->set_size(a->getSize());
      global_vars.insert({a->getOffset(), a->getMangledName()});
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
        "__libc_start_main"
    };

  for (ParseAPI::Function *func : code_object.funcs()) {
    if (shouldSkipFunction(func->name()))
      continue;
    else if (isExternal(func->entry()->start()))
      continue;
    //else if (func->name().substr(0, 4) == "targ")
    //  continue;

    // Add an entry in the protocol buffer

    auto cfgInternalFunc = module.add_funcs();

    ParseAPI::Block *entryBlock = func->entry();
    cfgInternalFunc->set_ea(entryBlock->start());

    cfgInternalFunc->set_is_entrypoint(
            notEntryPoints.find( func->name() ) == notEntryPoints.end() );

    for (ParseAPI::Block *block : func->blocks())
      writeBlock(block, func, cfgInternalFunc);

    if (func_map.find(func->addr()) != func_map.end()) {
      cfgInternalFunc->set_name(func_map[func->addr()]);
    }
  }
}

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

    if ((!found) || (edge->trg()->start() == -1))
      continue;

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

  // This variable "simulates" the instruction pointer
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
}

bool getDisplacement(InstructionAPI::Instruction *instruction,
                     std::set<InstructionAPI::Expression::Ptr> &operands,
                     Address &address) {
  bool found = false;

  for (auto &op : operands) {
    if (auto binFunc =
            dynamic_cast<InstructionAPI::BinaryFunction *>(op.get())) {

      std::vector<InstructionAPI::InstructionAST::Ptr> operands;
      binFunc->getChildren(operands);

      for (auto &a : operands) {
        if (auto second =
                dynamic_cast<InstructionAPI::BinaryFunction *>(a.get()))
          found = true;
      }

      if (auto addr =
              dynamic_cast<InstructionAPI::Immediate *>(operands[0].get()))
        address = addr->eval().convert<Address>();
    }
  }
  return found && address;
}

void writeDisplacement(mcsema::Instruction *cfgInstruction, Address &address,
        const std::string& name = "") {
  if ( !address ) return;

  AddCodeXref( cfgInstruction, CodeReference::DataTarget,
          CodeReference::MemoryDisplacementOperand, CodeReference::Internal,
          address, name );
}

void CFGWriter::checkDisplacement(Dyninst::InstructionAPI::Instruction *instruction,
                       mcsema::Instruction *cfgInstruction) {

  std::set<InstructionAPI::Expression::Ptr> memAccessors;
  Address address;

  instruction->getMemoryReadOperands(memAccessors);
  if (getDisplacement(instruction, memAccessors, address))
    writeDisplacement(cfgInstruction, address );

  instruction->getMemoryWriteOperands(memAccessors);
  if (getDisplacement(instruction, memAccessors, address))
    writeDisplacement(cfgInstruction, address );
}

void CFGWriter::getNoReturns() {
    for ( auto f : code_object.funcs() ) {
        if ( f->retstatus() == ParseAPI::NORETURN )
            no_ret_funcs.insert( f->name() );
    }
}

bool CFGWriter::isNoReturn( const std::string& name ) {
    return no_ret_funcs.find( name ) != no_ret_funcs.end();
}


std::string CFGWriter::getXrefName( Address addr ) {
    auto func = func_map.find( addr );
    if ( func != func_map.end() ) return func->second;

    auto extVar = external_vars.find( addr );
    if ( extVar != external_vars.end() ) return extVar->second;

    auto globalVar = global_vars.find( addr );
    if ( globalVar != global_vars.end() ) return globalVar->second;


    auto segmentVar = segment_vars.find( addr );
    if ( segmentVar != segment_vars.end() ) return segmentVar->second;

    return "__mcsema_unknown";
}


void CFGWriter::handleCallInstruction(InstructionAPI::Instruction *instruction,
                                      Address addr,
                                      mcsema::Instruction *cfgInstruction) {
  Address target;

  std::vector<InstructionAPI::Operand> operands;
  instruction->getOperands(operands);

  Address size = instruction->size();

  LOG(INFO) << "TryEval " << addr << " " << size;
  bool got_result = false;
  got_result = SmarterTryEval(operands[0].getValue().get(), addr, target, size);

  if (!got_result) {
    got_result = tryEval(operands[0].getValue().get(), addr + size, target);
    target -= size;
    LOG(INFO) << "Need old " << got_result;
    CHECK(!got_result) << "Truly needed old one!";
  }
  if (got_result) {
    //target -= size;

    /*if (isExternal(target)) {
       AddCodeXref(cfgInstruction,
                   CodeReference::CodeTarget,
                   CodeReference::ControlFlowOperand,
                   CodeReference::External, target,
                   getXrefName(target));

      if (isNoReturn( getExternalName(target))) {
        cfgInstruction->set_local_noreturn(true);
      }

      return;
    }*/
    handleXref(cfgInstruction, target);
    if (isNoReturn(getExternalName(target))) {
      cfgInstruction->set_local_noreturn(true);
    }
    return;
    LOG(INFO) << "It happened " << addr << " target: " << target;
  }
  LOG(INFO) << "Default " << addr;

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

  // TODO: This is when things like callq %*rcx happen, not sure yet how to deal
  // with it correctly, this seems to work good enough for now

  auto name = getXrefName(target);
  if (name == "__mcsema_unknown") {
    return;
  }
  AddCodeXref(cfgInstruction,
              CodeReference::CodeTarget,
              CodeReference::ControlFlowOperand,
              CodeReference::Internal,
              target, name);
}

void CFGWriter::immediateNonCall( InstructionAPI::Immediate* imm,
        Address addr, mcsema::Instruction* cfgInstruction ) {

    Address a = imm->eval().convert<Address>();
    auto allSymsAtOffset = symtab.findSymbolByOffset(a);
    bool isRef = false;

    if (allSymsAtOffset.size() > 0) {
      for (auto symbol : allSymsAtOffset) {
        if (symbol->getType() == SymtabAPI::Symbol::ST_OBJECT)
          isRef = true;
      }
    }

    // TODO: This is ugly hack from previous PR, but it works for now
    if (a > 0x1000) {
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
          external_vars.find(a) != external_vars.end()) {
            cfgCodeRef->set_location(CodeReference::External);
      }
  }
}

void CFGWriter::dereferenceNonCall(InstructionAPI::Dereference* deref,
                                   Address addr,
                                   mcsema::Instruction* cfgInstruction) {

      std::vector<InstructionAPI::InstructionAST::Ptr> children;
      deref->getChildren(children);
      auto expr = dynamic_cast<InstructionAPI::Expression *>(children[0].get());

      if (!expr) {
        throw std::runtime_error{"expected expression"};
      }

      Address a;
      if (tryEval(expr, addr, a)) {
        if (a > 0xffffffffffffff00) {
          return;
        }

        auto cfgCodeRef = AddCodeXref(cfgInstruction,
                                      CodeReference::DataTarget,
                                      CodeReference::MemoryOperand,
                                      CodeReference::Internal, a,
                                      getXrefName( a ) );
        if (isExternal(a) || external_vars.find(a) != external_vars.end())
            cfgCodeRef->set_location( CodeReference::External );
      }
}


void CFGWriter::handleXref(mcsema::Instruction *cfg_instruction,
                           Address addr) {
  auto func = func_map.find(addr);
  if (func != func_map.end()) {
    auto code_ref = AddCodeXref(cfg_instruction,
                                  CodeReference::CodeTarget,
                                  CodeReference::ControlFlowOperand,
                                  CodeReference::Internal, addr,
                                  func->second);
    if (isExternal(addr)) {
      code_ref->set_location(CodeReference::External);
    }
    return;
  }

  auto g_var = global_vars.find(addr);
  if (g_var != global_vars.end()) {
    auto code_ref = AddCodeXref(cfg_instruction,
                                  CodeReference::DataTarget,
                                  CodeReference::MemoryOperand,
                                  CodeReference::Internal, addr,
                                  g_var->second);
    return;
  }

  auto s_var = segment_vars.find(addr);
  if (s_var != segment_vars.end()) {
    auto code_ref = AddCodeXref(cfg_instruction,
                                  CodeReference::DataTarget,
                                  CodeReference::MemoryOperand,
                                  CodeReference::Internal, addr,
                                  s_var->second);
    return;
  }

  auto ext_var = external_vars.find(addr);
  if (ext_var != external_vars.end()) {
    auto code_ref = AddCodeXref(cfg_instruction,
                                  CodeReference::DataTarget,
                                  CodeReference::MemoryOperand,
                                  CodeReference::External, addr,
                                  ext_var->second);
    return;
  }
  LOG(INFO) << "Could not recognize xref anywhere falling to default";
  auto code_ref = AddCodeXref(cfg_instruction,
                                CodeReference::DataTarget,
                                CodeReference::MemoryOperand,
                                CodeReference::Internal, addr);
  if (isExternal(addr)) {
    code_ref->set_location(CodeReference::External);
  }
}

void CFGWriter::handleNonCallInstruction(
    Dyninst::InstructionAPI::Instruction *instruction,
    Address addr,
    mcsema::Instruction *cfgInstruction) {

  std::vector<InstructionAPI::Operand> operands;
  instruction->getOperands(operands);

  // RIP already points to the next instruction
  addr += instruction->size();

  for (auto op : operands) {
    auto expr = op.getValue();

    if (auto imm = dynamic_cast<InstructionAPI::Immediate *>(expr.get())) {
      immediateNonCall( imm, addr, cfgInstruction);
    } else if (
        auto deref = dynamic_cast<InstructionAPI::Dereference *>(expr.get())) {
      dereferenceNonCall( deref, addr, cfgInstruction);
    } else if (
        auto bf = dynamic_cast<InstructionAPI::BinaryFunction *>(expr.get())) {

      // 268 stands for lea
      // 8 stands for jump
      auto instruction_id = instruction->getOperation().getID();
      if (instruction_id == 268) {
        Address a;
        if (addr - instruction->size() == 0x405c7d) {
          auto xref = AddCodeXref(cfgInstruction,
                                  CodeReference::DataTarget,
                                  CodeReference::MemoryDisplacementOperand,
                                  CodeReference::Internal, 6618560);
        }
        //addr -= instruction->size();
        LOG(INFO) << "PoT";
        if(tryEval(expr.get(), addr, a)) {
          handleXref(cfgInstruction, a);
        }
      } else if (instruction_id == 8) {
        Address a;
        if (tryEval(expr.get(), addr - instruction->size(), a)) {
          auto code_ref = AddCodeXref(cfgInstruction,
                                      CodeReference::CodeTarget,
                                      CodeReference::ControlFlowOperand,
                                      CodeReference::Internal, a);
          if (isExternal(a)) {
            code_ref->set_location(CodeReference::External);
            code_ref->set_name(getXrefName(a));
          }
        }
      }
    }
  }
  checkDisplacement(instruction, cfgInstruction);
}

void CFGWriter::writeExternalFunctions() {
  std::vector<std::string> unknown;
  auto known = ext_func_manager.GetAllUsed( unknown );
  LOG(INFO) << "Found " << known.size() << " external functions";
  LOG(INFO) << "Found " << unknown.size()
            << "possibly unknown external functions";

  for (auto &name : unknown) {
    known.push_back({name});
    LOG(INFO) << "Possibly unknown external " << name;
  }

  for (auto &func : known) {
    Address a;
    bool found = false;

    for (auto p : code_object.cs()->linkage()) {
      if (p.second == func.symbol_name) {
        found = true;
        a = p.first;
        break;
      }
    }

    if (!found) {
      throw std::runtime_error{"unresolved external function call"};
    }
    auto cfgExtFunc = module.add_external_funcs();

    cfgExtFunc->set_name(func.symbol_name);
    cfgExtFunc->set_ea(a);
    cfgExtFunc->set_cc(func.CfgCallingConvention());
    cfgExtFunc->set_has_return(func.has_return);
    cfgExtFunc->set_no_return(!func.has_return);
    cfgExtFunc->set_argument_count(func.arg_count);
    cfgExtFunc->set_is_weak(func.is_weak);
  }
}

bool IsInRegion(SymtabAPI::Region *r, Address a) {
  if (a < r->getMemOffset()) return false;
  if (a > (r->getMemOffset() + r->getMemSize())) return false;
  return true;
}

bool IsInBinary(ParseAPI::CodeSource &code_source, Address a) {
  for (auto &r : code_source.regions()) {
    if (r->contains(a)) {
      return true;
    }
  }
  LOG(INFO) << std::hex << a << std::dec << " is not contained in code_source";
  return false;
}


bool FishForXref(CFGWriter::SymbolMap vars,
                 const CFGWriter::CrossXref &xref,
                 bool is_code=false, uint64_t width=8) {
  auto var = vars.find(xref.target_ea);
  if (var != vars.end()) {
    auto cfg_xref = xref.segment->add_xrefs();
    cfg_xref->set_ea(xref.ea);
    cfg_xref->set_width(width);
    cfg_xref->set_target_ea(xref.target_ea);
    cfg_xref->set_target_name(var->second);
    cfg_xref->set_target_is_code(is_code);
    cfg_xref->set_target_fixup_kind(mcsema::DataReference::Absolute);
    return true;
  }
  return false;
}

bool CFGWriter::handleDataXref(mcsema::Segment *segment,
                               Address ea,
                               Address target) {
  CrossXref xref = {ea, target, segment};

  if (FishForXref(segment_vars ,xref)) {
    found_xref.insert(ea);
    return true;
  }

  if (FishForXref(func_map, xref)) {
    found_xref.insert(ea);
    return true;
  }

  if (FishForXref(external_vars, xref)) {
    found_xref.insert(ea);
    return true;
  }

  if (FishForXref(global_vars, xref)) {
    found_xref.insert(ea);
    return true;
  }
  return false;

}

//TODO(lukas): This is finding vars actually?
void CFGWriter::tryParseVariables(SymtabAPI::Region *region, mcsema::Segment *segment) {
  std::string base_name = region->getRegionName();
  static int counter = 0;
  static int unnamed = 0;
  auto offset = static_cast<uint8_t *>(region->getPtrToRawData());
  auto end = offset + region->getDiskSize();

  for (int j = 0; j < region->getDiskSize(); j += 1, ++offset) {
    CHECK(region->getMemOffset() + j == region->getDiskOffset() + j) << "Disk and mem";

    if (*offset == 0) {
      continue;
    }
    uint64_t size = j;
    while (*offset != 0) {
      ++j;
      ++offset;
      if (offset + size == end) return;
    }

    auto diff = j - size;
    if (diff <= 4 && diff >= 3) {

      auto tmp_ptr = reinterpret_cast<std::uint64_t *>(static_cast<uint8_t *>(region->getPtrToRawData()) + size);
      if (handleDataXref(segment, region->getMemOffset() + size, *tmp_ptr)) {
        LOG(INFO) << "Fished up " << std::hex << *tmp_ptr << std::dec;
        continue;
      }

      if (IsInRegion(region, *tmp_ptr)) {
        LOG(INFO) << "\tFound unnamed xref at " << region->getMemOffset() + size;
        LOG(INFO) << "Pointing to " << *tmp_ptr;
        std::string name = base_name + "_unnamed_" + std::to_string(++unnamed);

        auto xref = segment->add_xrefs();
        xref->set_ea(region->getMemOffset() + size);
        //TODO(lukas): Probably should not be hardcoded
        xref->set_width(8);
        xref->set_target_ea(*tmp_ptr);
        xref->set_target_name(name);
        xref->set_target_is_code(false); // TODO: Check
        xref->set_target_fixup_kind(mcsema::DataReference::Absolute);

        //Now add target as var
        auto cfg_var = segment->add_vars();
        cfg_var->set_name(name);
        cfg_var->set_ea(*tmp_ptr);
        segment_vars.insert({*tmp_ptr, name});
        found_xref.insert(region->getMemOffset() + size);
        continue;
      } else if (IsInBinary(code_source, *tmp_ptr)) {
        LOG(INFO) << "Cross xref " << std::hex << *tmp_ptr << std::dec;
        cross_xrefs.push_back({region->getMemOffset() + size, *tmp_ptr, segment});
        continue;
      }
    }
    std::string name = base_name + "_" + std::to_string(counter);
    ++counter;
    auto var = segment->add_vars();
    var->set_ea(region->getMemOffset() + size);
    var->set_name(name);
    segment_vars.insert({region->getMemOffset() + size, name});
  }
}

void CFGWriter::xrefsInSegment(SymtabAPI::Region *region,
                               mcsema::Segment *segment) {

  if (region->getRegionName() == ".rodata" ||
      region->getRegionName() == ".data") {
    LOG(INFO) << "Point of interest";
    //return;
  }

  auto offset = static_cast<std::uint64_t*>(region->getPtrToRawData());

  for (int j = 0; j < region->getDiskSize(); j += 8, offset++) {

    //SymtabAPI::Function* func;
    //if (!symtab.findFuncByEntryOffset(func, *offset)){
    //  continue;
    //}
    auto func = func_map.find(*offset);
    if (func != func_map.end()) {
      if (found_xref.count(region->getMemOffset() +j)) {
        LOG(WARNING) << "Dual xref detected!";
        continue;
      } else {
        LOG(WARNING) << "Unique";
      }
      LOG(INFO) << "Founf func xref at " << region->getMemOffset() + j;
      auto xref = segment->add_xrefs();
      xref->set_ea(region->getMemOffset() + j);
      //TODO(lukas): Probably should not be hardcoded
      xref->set_width(8);
      xref->set_target_ea(*offset);
      xref->set_target_name(func->second);
      xref->set_target_is_code(true); // TODO: Check
      xref->set_target_fixup_kind(mcsema::DataReference::Absolute);
    }

    auto var = segment_vars.find(*offset);
    if (var != segment_vars.end()) {
      if (found_xref.count(region->getMemOffset() +j)) {
        LOG(WARNING) << "Dual xref detected!";
        continue;
      } else {
        LOG(WARNING) << "Unique";
      }
      LOG(INFO) << "Founf segment var xref at " << region->getMemOffset() + j;
      auto xref = segment->add_xrefs();
      xref->set_ea(region->getMemOffset() + j);
      //TODO(lukas): Probably should not be hardcoded
      xref->set_width(8);
      xref->set_target_ea(*offset);
      xref->set_target_name(var->second);
      xref->set_target_is_code(false); // TODO: Check
      xref->set_target_fixup_kind(mcsema::DataReference::Absolute);
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

void CFGWriter::writeRelocations(SymtabAPI::Region* region,
                                 mcsema::Segment* cfgInternalData) {
  const auto &relocations = region->getRelocations();

  for (auto reloc : relocations) {
    for (auto f : code_object.funcs()) {
      if (f->entry()->start() == reloc.getDynSym()->getOffset()) {
        auto cfgSymbol = cfgInternalData->add_xrefs();
        cfgSymbol->set_ea(reloc.rel_addr());
        //TODO(lukas): Probably should not be hardcoded
        cfgSymbol->set_width(8);
        cfgSymbol->set_target_ea(reloc.getDynSym()->getOffset());
        cfgSymbol->set_target_name(f->name());
        cfgSymbol->set_target_is_code(true);

        cfgSymbol->set_target_fixup_kind(mcsema::DataReference::Absolute);

        break;
      }
    }
  }
}

void CFGWriter::ResolveCrossXrefs() {
  for (auto &xref : cross_xrefs) {
    auto g_var = global_vars.find(xref.target_ea);
    if (g_var != global_vars.end()) {
      LOG(ERROR) << "It is to global";
      continue;
    }

    auto s_var = segment_vars.find(xref.target_ea);
    if (s_var != segment_vars.end()) {
      auto cfg_xref = xref.segment->add_xrefs();
      cfg_xref->set_target_name(s_var->second);
      cfg_xref->set_ea(xref.ea);
      cfg_xref->set_target_ea(xref.target_ea);
      cfg_xref->set_target_is_code(false);
      cfg_xref->set_width(8);
      cfg_xref->set_target_fixup_kind(mcsema::DataReference::Absolute);
      continue;
    }
    LOG(WARNING) << std::hex << xref.ea << " is unresolved, targeting " << xref.target_ea << std::dec;
  }
}

void writeBssXrefs(SymtabAPI::Region *region,
                   mcsema::Segment *segment,
                   const CFGWriter::SymbolMap &externals) {
  for (auto &external : externals) {
    LOG(INFO) << "Trying " << std::hex << external.first << std::dec;
    if (IsInRegion(region, external.first)) {
      LOG(INFO) << "\tWriting " << std::hex << external.first << std::dec;
      auto cfg_xref = segment->add_xrefs();
      cfg_xref->set_ea(external.first);
      cfg_xref->set_width(8);
      cfg_xref->set_target_ea(external.first);
      cfg_xref->set_target_name(external.second);
      cfg_xref->set_target_is_code(false);
      cfg_xref->set_target_fixup_kind(mcsema::DataReference::Absolute);
    }
  }
}

void CFGWriter::writeInternalData() {
  auto dataRegions = section_manager.GetDataRegions();

  for (auto region : dataRegions) {
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

    writeDataVariables(region, cfgInternalData);

    xrefsInSegment( region, cfgInternalData );

    if (region->getRegionName() == ".bss") {
      writeBssXrefs(region, cfgInternalData, external_vars);
    }

    if (region->getRegionName() == ".got.plt")
      writeRelocations(region, cfgInternalData);
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

      if (external_vars.find(a->getOffset()) != external_vars.end()) {
        continue;
      }

      auto var = segment->add_vars();
      var->set_ea(a->getOffset());
      var->set_name(a->getMangledName());

      segment_vars.insert({a->getOffset(), a->getMangledName()});
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
    is = ext_func_manager.IsExternal(code_object.cs()->linkage()[addr]);
  }

  if (external_vars.find(addr) != external_vars.end()) {
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


bool CFGWriter::SmarterTryEval(InstructionAPI::Expression *expr,
                        const Address ip,
                        Address &result,
                        Address instruction_size) const {
  InstructionAPI::RegisterAST rip =
      InstructionAPI::RegisterAST::makePC(Dyninst::Arch_x86_64);
  auto ip_value = InstructionAPI::Result(InstructionAPI::u64, ip);
  expr->bind(&rip, ip_value);

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

    auto first = SmarterTryEval(
        dynamic_cast<InstructionAPI::Expression *>(args[0].get()),
        ip, left);
    auto second = SmarterTryEval(
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
    return SmarterTryEval(dynamic_cast<InstructionAPI::Expression *>(args[0].get()),
                   ip + instruction_size,
                   result);
  }
  LOG(INFO) << "ERR";
  return false;
}
