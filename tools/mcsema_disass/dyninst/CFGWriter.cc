#include "CFGWriter.hpp"

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

#include "Util.hpp"

using namespace Dyninst;
using namespace mcsema;

CFGWriter::CFGWriter(mcsema::Module &m, const std::string &moduleName,
                     SymtabAPI::Symtab &symtab, 
                     ParseAPI::SymtabCodeSource &symCodeSrc,
                     ParseAPI::CodeObject &codeObj,
                     const ExternalFunctionManager &extFuncMgr)
    : m_module(m), m_moduleName(moduleName), m_symtab(symtab), m_codeSource( symCodeSrc ),
      m_codeObj(codeObj), m_extFuncMgr(extFuncMgr), m_funcMap(), m_skipFuncs(),
      m_sectionMgr(), m_relocations() {
  // Populate m_funcMap

  std::vector<SymtabAPI::Function *> functions;
  m_symtab.getAllFunctions(functions);

  for (auto func : functions)
    m_funcMap[func->getOffset()] = *(func->mangled_names_begin());

  // Populate m_skipFuncs with some functions known to cause problems

  m_skipFuncs = {
                 "_fini",
                 "__libc_start_main"
                 };

  std::vector<SymtabAPI::Region *> regions;
  symtab.getAllRegions(regions);

  for (auto reg : regions) {
      m_sectionMgr.addRegion(reg);
  }

  for (auto reg : regions) {
    if (reg->getRegionName() == ".text")
      m_relocations = reg->getRelocations();
  }

  getNoReturns();
}
/*
void CFGWriter::skipFunction(const std::string &name) {
  m_skipFuncs.insert(name);
}
*/
void CFGWriter::write() {
  writeExternalVariables();
  writeInternalData();
  writeGlobalVariables();
  
  writeInternalFunctions();
  writeExternalFunctions();
  
  m_module.set_name(m_moduleName);
}

void CFGWriter::writeExternalVariables() {
  std::vector<SymtabAPI::Symbol *> symbols;
  m_symtab.getAllSymbolsByType(symbols, SymtabAPI::Symbol::ST_OBJECT);
  
  for (const auto &s : symbols) {
    if (s->isInDynSymtab()) {
      m_externalVars.insert( { s->getOffset(), s } );
      
      auto extVar = m_module.add_external_vars();
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
      
      auto globalVar = m_module.add_global_vars();
      globalVar->set_ea(a->getOffset());
      globalVar->set_name(a->getMangledName());
      globalVar->set_size(a->getSize());
      m_globalVars.insert({a->getOffset(), a});
    }
  }
}

bool CFGWriter::shouldSkipFunction(const std::string &name) const {
  return m_skipFuncs.find(name) != m_skipFuncs.end();
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
    
  for (ParseAPI::Function *func : m_codeObj.funcs()) {
    if (shouldSkipFunction(func->name()))
      continue;
    else if (isExternal(func->entry()->start()))
      continue;
    else if (func->name().substr(0, 4) == "targ")
      continue;

    // Add an entry in the protocol buffer

    auto cfgInternalFunc = m_module.add_funcs();

    ParseAPI::Block *entryBlock = func->entry();
    cfgInternalFunc->set_ea(entryBlock->start());

    cfgInternalFunc->set_is_entrypoint(
            notEntryPoints.find( func->name() ) == notEntryPoints.end() );

    for (ParseAPI::Block *block : func->blocks())
      writeBlock(block, func, cfgInternalFunc);

    if (m_funcMap.find(func->addr()) != m_funcMap.end()) {
      cfgInternalFunc->set_name(m_funcMap[func->addr()]);
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

  if (instruction->getCategory() == InstructionAPI::c_CallInsn)
    handleCallInstruction(instruction, addr, cfgInstruction);
  else
    handleNonCallInstruction(instruction, addr, cfgInstruction);
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

  addCodeXref( cfgInstruction, CodeReference::DataTarget,
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
    for ( auto f : m_codeObj.funcs() ) {
        if ( f->retstatus() == ParseAPI::NORETURN )
            m_noreturnFunctions.insert( f->name() );
    }
}

bool CFGWriter::isNoReturn( const std::string& name ) {
    return m_noreturnFunctions.find( name ) != m_noreturnFunctions.end();
}


std::string CFGWriter::getXrefName( Address addr ) {
    auto func = m_funcMap.find( addr );
    if ( func != m_funcMap.end() ) return func->second;
    
    auto extVar = m_externalVars.find( addr );
    if ( extVar != m_externalVars.end() ) return extVar->second->getMangledName();

    auto globalVar = m_globalVars.find( addr );
    if ( globalVar != m_globalVars.end() ) return globalVar->second->getMangledName();


    auto segmentVar = m_segmentVars.find( addr );
    if ( segmentVar != m_segmentVars.end() ) return segmentVar->second->getMangledName();

    return "__mcsema_unknown";
}


void CFGWriter::handleCallInstruction(InstructionAPI::Instruction *instruction,
                                      Address addr,
                                      mcsema::Instruction *cfgInstruction) {
  Address target;

  std::vector<InstructionAPI::Operand> operands;
  instruction->getOperands(operands);

  Address size = instruction->size();
  
  if (tryEval(operands[0].getValue().get(), addr + size, target)) {
    target -= size;

    if (isExternal(target)) {
       addCodeXref( cfgInstruction, CodeReference::CodeTarget,
              CodeReference::ControlFlowOperand, CodeReference::External, target,
              getXrefName(target));
      
      if ( isNoReturn( getExternalName( target ) ) )
        cfgInstruction->set_local_noreturn( true );
      
      return;
    }
  }

  if (m_relocations.size() > 0) {
    auto entry = *(m_relocations.begin());
    bool found = false;

    for (auto ent : m_relocations) {
      if (ent.rel_addr() == (addr + size + 1)) {
        entry = ent;
        found = true;
        break;
      }
    }

    if (!((!found) || (found && !entry.getDynSym()->getRegion()))) {
        Offset off = entry.getDynSym()->getOffset();
        
        addCodeXref( cfgInstruction, CodeReference::CodeTarget,
                CodeReference::ControlFlowOperand, CodeReference::Internal, off );      
      return;
    }
  }

  // TODO: This is when things like callq %*rcx happen, not sure yet how to deal
  // with it correctly, this seems to work good enough for now
  
  auto name = getXrefName( target ); 
  if ( name == "__mcsema_unknown" ) return; 
  addCodeXref( cfgInstruction, CodeReference::CodeTarget,
          CodeReference::ControlFlowOperand, CodeReference::Internal, target, name );
   
}

void CFGWriter::immediateNonCall( InstructionAPI::Immediate* imm,
        Address addr, mcsema::Instruction* cfgInstruction ) {
    
    Address a = imm->eval().convert<Address>();
    auto allSymsAtOffset = m_symtab.findSymbolByOffset(a);
    bool isRef = false;
    
    if (allSymsAtOffset.size() > 0) {
      for (auto symbol : allSymsAtOffset) {
        if (symbol->getType() == SymtabAPI::Symbol::ST_OBJECT)
          isRef = true;
      }
    }

    // TODO: This is ugly hack from previous PR, but it works,
    // would be nice to work around it
    
    if (a > 0x1000)
      isRef = true;
    if ( a > 0xffffffffffffff00 )
      isRef = false;
  
    if ( isRef ) {
      auto cfgCodeRef = addCodeXref( cfgInstruction, CodeReference::DataTarget,
              CodeReference::ImmediateOperand, CodeReference::Internal, a, getXrefName( a ) );  
      if ( isExternal( a ) || m_externalVars.find( a ) != m_externalVars.end() )
            cfgCodeRef->set_location( CodeReference::External );
  }
}

void CFGWriter::dereferenceNonCall( InstructionAPI::Dereference* deref,
        Address addr, mcsema::Instruction* cfgInstruction ) {

       std::vector<InstructionAPI::InstructionAST::Ptr> children;
      deref->getChildren(children);
      auto expr = dynamic_cast<InstructionAPI::Expression *>(children[0].get());
      
      if ( !expr )
        throw std::runtime_error{"expected expression"};

      Address a;
      if (tryEval(expr, addr, a)) {
        if ( a > 0xffffffffffffff00 ) return;
       
        auto cfgCodeRef = addCodeXref( cfgInstruction, CodeReference::DataTarget, CodeReference::MemoryOperand,
               CodeReference::Internal, a, getXrefName( a ) );
        if ( isExternal( a ) || m_externalVars.find( a ) != m_externalVars.end() )
            cfgCodeRef->set_location( CodeReference::External );
      }
}


void CFGWriter::handleNonCallInstruction(
    Dyninst::InstructionAPI::Instruction *instruction, Address addr,
    mcsema::Instruction *cfgInstruction) {
  
  std::vector<InstructionAPI::Operand> operands;
  instruction->getOperands(operands);
   
  // RIP already points to the next instruction 
  addr += instruction->size();

  for (auto op : operands) {
    auto expr = op.getValue();

    if (auto imm = dynamic_cast<InstructionAPI::Immediate *>(expr.get())) {
        immediateNonCall( imm, addr, cfgInstruction );      
    } else if (auto deref =
                   dynamic_cast<InstructionAPI::Dereference *>(expr.get())) {
        dereferenceNonCall( deref, addr, cfgInstruction );
    } else if (auto bf = dynamic_cast<InstructionAPI::BinaryFunction *>(expr.get())) {
        // 268 stands for lea
        if ( instruction->getOperation().getID() != 268 ) continue;
        Address a;
        if( tryEval( expr.get(), addr, a) ) {
            auto cfgCodeRef = addCodeXref( cfgInstruction, CodeReference::DataTarget, CodeReference::MemoryOperand,
                CodeReference::Internal, a, getXrefName( a ) );
            if ( isExternal( a ) || m_externalVars.find( a ) != m_externalVars.end() )
                cfgCodeRef->set_location( CodeReference::External );        
        }
    }
  }
  checkDisplacement(instruction, cfgInstruction);
}

void CFGWriter::writeExternalFunctions() {
  for (const auto &func : m_extFuncMgr.getAllUsed()) {
    Address a;
    bool found = false;

    for (auto p : m_codeObj.cs()->linkage()) {
      if (p.second == func.symbolName()) {
        found = true;
        a = p.first;
        break;
      }
    }

    if (!found)
      throw std::runtime_error{"unresolved external function call"};

    auto cfgExtFunc = m_module.add_external_funcs();

    cfgExtFunc->set_name(func.symbolName());
    cfgExtFunc->set_ea(a);
    cfgExtFunc->set_cc(func.cfgCallingConvention());
    cfgExtFunc->set_has_return(func.hasReturn());
    cfgExtFunc->set_no_return(func.noReturn());
    cfgExtFunc->set_argument_count(func.argumentCount());
    cfgExtFunc->set_is_weak(func.isWeak());
  }
}

void CFGWriter::xrefsInSegment( SymtabAPI::Region* region, mcsema::Segment* segment ) {
    auto ea = region->getMemOffset();

    std::uint64_t* offset = ( std::uint64_t* )region->getPtrToRawData();
    for ( int j = 0; j < region->getDiskSize(); j += 8, offset++ ) {
        
        SymtabAPI::Function* func;
        if ( !m_symtab.findFuncByEntryOffset( func, *offset ) ) continue;
        
        auto xref = segment->add_xrefs();
        xref->set_ea( region->getMemOffset()  + j );
        xref->set_width( 8 );
        xref->set_target_ea( *offset );
        xref->set_target_name( func->getName() );
        xref->set_target_is_code( true ); // TODO: Check
        xref->set_target_fixup_kind( mcsema::DataReference::Absolute );
    }
}

void writeRawData( std::string& data, SymtabAPI::Region* region ) {
    int i = 0;

    for (; i < region->getDiskSize(); ++i)
      data += ((const char *)region->getPtrToRawData())[i];

    // Zero padding
    for (; i < region->getMemSize(); ++i)
      data += '\0';
}

void CFGWriter::writeRelocations( SymtabAPI::Region* region, mcsema::Segment* cfgInternalData ) {
    const auto &relocations = region->getRelocations();

    for (auto reloc : relocations) {
        for (auto f : m_codeObj.funcs()) {
            if (f->entry()->start() == reloc.getDynSym()->getOffset()) {
                auto cfgSymbol = cfgInternalData->add_xrefs();
                cfgSymbol->set_ea(reloc.rel_addr());
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

void CFGWriter::writeInternalData() {
  auto dataRegions = m_sectionMgr.getDataRegions();

  for (auto region : dataRegions) {
    // Sanity check
    if (region->getMemSize() <= 0)
      continue;

    if ( region->getRegionName() == ".fini_array" ) continue;
    auto cfgInternalData = m_module.add_segments();

    std::string data;
    writeRawData( data, region );

    // .init & .fini should be together
    if ( region->getRegionName() == ".init_array" ) {
        SymtabAPI::Region* fini;
        m_symtab.findRegion( fini, ".fini_array" );
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
    
    if (region->getRegionName() == ".got.plt")
        writeRelocations( region, cfgInternalData );
  }
}

void CFGWriter::writeDataVariables(Dyninst::SymtabAPI::Region *region,
                                   mcsema::Segment *segment) {
  std::vector<SymtabAPI::Symbol *> vars;
  m_symtab.getAllSymbolsByType(vars, SymtabAPI::Symbol::ST_OBJECT);
  
  for (auto &a : vars) {
    if ((a->getRegion() && a->getRegion() == region) ||
        (a->getOffset() == region->getMemOffset()) ) {
      
      if ( m_externalVars.find( a->getOffset() ) != m_externalVars.end() )
        continue;
      
      auto var = segment->add_vars();
      var->set_ea(a->getOffset());
      var->set_name(a->getMangledName());
      
      m_segmentVars.insert({ a->getOffset(), a });
    }
  }
}


bool CFGWriter::isExternal(Address addr) const {
  bool is = false;
  if (m_codeObj.cs()->linkage().find(addr) != m_codeObj.cs()->linkage().end()) {
    is = m_extFuncMgr.isExternal(m_codeObj.cs()->linkage()[addr]);
  }
  
  if ( m_externalVars.find(addr) != m_externalVars.end() )
      is  = true;

  return is;
}

const std::string &CFGWriter::getExternalName(Address addr) const {
  return m_codeObj.cs()->linkage().at(addr);
}

bool CFGWriter::tryEval(InstructionAPI::Expression *expr, const Address ip,
                        Address &result) const {
  if (expr->eval().format() != "[empty]") {
    result = expr->eval().convert<Address>();
    return true;
  }

  if (auto bin = dynamic_cast<InstructionAPI::BinaryFunction *>(expr)) {
    std::vector<InstructionAPI::InstructionAST::Ptr> args;
    bin->getChildren(args);

    Address left, right;

    if (tryEval(dynamic_cast<InstructionAPI::Expression *>(args[0].get()), ip,
                left) &&
        tryEval(dynamic_cast<InstructionAPI::Expression *>(args[1].get()), ip,
                right)) {
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
      result = ip;
      return true;
    }
  } else if ( auto imm = dynamic_cast< InstructionAPI::Immediate* >( expr ) ) {
    result = imm->eval().convert<Address>();
    return true;
  }

  return false;
}
