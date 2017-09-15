#include "CFGWriter.hpp"
#include <Dereference.h>
#include <Function.h>
#include <Instruction.h>
#include <InstructionAST.h>
#include <InstructionCategories.h>
#include <sstream>

using namespace Dyninst;

CFGWriter::CFGWriter (mcsema::Module& m, const std::string& moduleName,
                      SymtabAPI::Symtab& symtab,
                      ParseAPI::CodeObject& codeObj,
                      const ExternalFunctionManager& extFuncMgr)
    : m_module (m), m_moduleName (moduleName), m_symtab (symtab),
      m_codeObj (codeObj), m_extFuncMgr (extFuncMgr), m_funcMap (),
      m_skipFuncs (), m_sectionMgr (), m_relocations ()
{
    // Populate m_funcMap

    std::vector<SymtabAPI::Function *> functions;
    m_symtab.getAllFunctions (functions);

    for (auto func : functions)
        m_funcMap [func->getOffset ()] = *(func->mangled_names_begin ());

    // Populate m_skipFuncs with some functions known to cause problems

    m_skipFuncs = { "register_tm_clones", "deregister_tm_clones", "__libc_csu_init",
                    "frame_dummy", "_init", "_start", "__do_global_dtors_aux",
                    "__libc_csu_fini", "_fini", "__libc_start_main" };

    // Populate m_sectionMgr with the data from symtab

    std::vector<SymtabAPI::Region *> regions;
    symtab.getAllRegions (regions);

    for (auto reg : regions)
        m_sectionMgr.addRegion (reg);

    // Fill in m_relocations

    for (auto reg : regions)
    {
        if (reg->getRegionName () == ".text")
            m_relocations = reg->getRelocations ();
    }
}

void CFGWriter::skipFunction (const std::string& name)
{
    m_skipFuncs.insert (name);
}

void CFGWriter::write ()
{
    writeInternalFunctions ();
    writeExternalFunctions ();
    writeInternalData ();
    m_module.set_name (m_moduleName);
}

bool CFGWriter::shouldSkipFunction (const std::string& name) const
{
    return m_skipFuncs.find (name) != m_skipFuncs.end ();
}

void CFGWriter::writeInternalFunctions ()
{
    for (ParseAPI::Function *func : m_codeObj.funcs ())
    {
        if (shouldSkipFunction (func->name ()))
            continue;
        else if (isExternal (func->entry ()->start ()))
            continue;

        // Add an entry in the protocol buffer

        auto cfgInternalFunc = m_module.add_funcs ();

        // Set the entry address

        ParseAPI::Block *entryBlock = func->entry ();
        cfgInternalFunc->set_ea (entryBlock->start ());

        cfgInternalFunc->set_is_entrypoint (true); /* TODO */

        // Write blocks

        for (ParseAPI::Block *block : func->blocks ())
            writeBlock (block, func, cfgInternalFunc);

        if (m_funcMap.find (func->addr ()) != m_funcMap.end ())
            cfgInternalFunc->set_name (m_funcMap [func->addr ()]);
    }
}

void CFGWriter::writeBlock (ParseAPI::Block *block, ParseAPI::Function *func,
                            mcsema::Function *cfgInternalFunc)
{
    // Add a new block to the protocol buffer and set its base address

    mcsema::Block *cfgBlock = cfgInternalFunc->add_blocks ();
    cfgBlock->set_ea (block->start ());

    // Set outgoing edges

    for (auto edge : block->targets ())
    {
        // Is this block part of the current function?

        bool found = false;

        for (auto bl : func->blocks ())
        {
            if (bl->start () == edge->trg ()->start ())
            {
                found = true;
                break;
            }
        }

        if ((!found) || (edge->trg ()->start () == -1))
            continue;

        // Handle recursive calls

        found = false;

        if (edge->trg ()->start () == func->entry ()->start ())
        {
            for (auto callEdge : func->callEdges ())
            {
                if ((callEdge->src ()->start () == block->start ())
                    && (callEdge->trg ()->start () == func->entry ()->start ()))
                {
                    // Looks like a recursive call, so no block_follows edge here
                    found = true;
                    break;
                }
            }
        }

        if (!found)
            cfgBlock->add_successor_eas (edge->trg ()->start ());
    }

    // Write instructions

    std::map<Offset, InstructionAPI::Instruction::Ptr> instructions;
    block->getInsns (instructions);

    // This variable "simulates" the instruction pointer
    Address ip = block->start ();

    for (auto p : instructions)
    {
        InstructionAPI::Instruction *instruction = p.second.get ();

        writeInstruction (instruction, ip, cfgBlock);
        ip += instruction->size ();
    }
}

void CFGWriter::writeInstruction (InstructionAPI::Instruction *instruction,
                                  Address addr, mcsema::Block *cfgBlock)
{
    // Add a new instruction to the protocol buffer

    mcsema::Instruction *cfgInstruction = cfgBlock->add_instructions ();

    // Set the raw instruction bytes

    std::string instBytes;

    for (int offset = 0; offset < instruction->size (); ++offset)
        instBytes += instruction->rawByte (offset);

    cfgInstruction->set_bytes (instBytes);

    // Set the instruction address

    cfgInstruction->set_ea (addr);

    cfgInstruction->set_local_noreturn (false); // TODO

    // Handle the instruction's operands

    std::vector<InstructionAPI::Operand> operands;
    instruction->getOperands (operands);

    if (instruction->getCategory () == InstructionAPI::c_CallInsn)
        handleCallInstruction (instruction, addr, cfgInstruction);
    else
        handleNonCallInstruction (instruction, addr, cfgInstruction);
}

void CFGWriter::handleCallInstruction (InstructionAPI::Instruction *instruction,
                                       Address addr, mcsema::Instruction *cfgInstruction)
{
    Address target;

    std::vector<InstructionAPI::Operand> operands;
    instruction->getOperands (operands);

    if (tryEval (operands [0].getValue ().get (), addr + 5, target))
    {
        target -= 5;

        if (isExternal (target))
        {
            auto cfgCodeRef = cfgInstruction->add_xrefs ();
            cfgCodeRef->set_target_type (mcsema::CodeReference::CodeTarget);
            cfgCodeRef->set_operand_type (mcsema::CodeReference::ControlFlowOperand);
            cfgCodeRef->set_location (mcsema::CodeReference::External);
            cfgCodeRef->set_ea (target);
            cfgCodeRef->set_name (getExternalName (target));

            return;
        }
    }

    if (m_relocations.size () > 0)
    {
        auto entry = *(m_relocations.begin ());
        bool found = false;

        for (auto ent : m_relocations)
        {
            if (ent.rel_addr () == (addr + 6))
            {
                entry = ent;
                found = true;
                break;
            }
        }

        if (!((!found) || (found && (entry.getDynSym ()->getRegion () == NULL))))
        {
            Offset off = entry.getDynSym ()->getOffset ();

            auto cfgCodeRef = cfgInstruction->add_xrefs ();
            cfgCodeRef->set_target_type (mcsema::CodeReference::CodeTarget);
            cfgCodeRef->set_operand_type (mcsema::CodeReference::ControlFlowOperand);
            cfgCodeRef->set_location (mcsema::CodeReference::Internal);
            cfgCodeRef->set_ea (off);

            return;
        }
    }

    if (tryEval (operands [0].getValue ().get (), addr + 5, target))
    {
        target -= 5;

        auto cfgCodeRef = cfgInstruction->add_xrefs ();
        cfgCodeRef->set_target_type (mcsema::CodeReference::CodeTarget);
        cfgCodeRef->set_operand_type (mcsema::CodeReference::ControlFlowOperand);
        cfgCodeRef->set_location (mcsema::CodeReference::Internal);
        cfgCodeRef->set_ea (target);

        return;
    }

    std::cerr << "error: unable to resolve call instruction at 0x"
              << std::hex << addr << std::dec << std::endl;
    throw std::runtime_error { "unresolved call instruction" };
}

void CFGWriter::handleNonCallInstruction (Dyninst::InstructionAPI::Instruction *instruction,
                                          Address addr, mcsema::Instruction *cfgInstruction)
{
    std::vector<InstructionAPI::Operand> operands;
    instruction->getOperands (operands);
    addr += instruction->size ();

    for (auto op : operands)
    {
        auto expr = op.getValue ();

        if (auto imm = dynamic_cast<InstructionAPI::Immediate *> (expr.get ()))
        {
            Address a = imm->eval ().convert<Address> ();
            if (m_sectionMgr.isData (a))
            {
                auto allSymsAtOffset = m_symtab.findSymbolByOffset (a);
                bool isRef = false;
                if (allSymsAtOffset.size () > 0)
                {
                    for (auto symbol : allSymsAtOffset)
                    {
                        if (symbol->getType () == SymtabAPI::Symbol::ST_OBJECT)
                            isRef = true;
                    }
                }

                if (a > 0x1000)
                    isRef = true;

                if (isRef)
                {
                    auto cfgCodeRef = cfgInstruction->add_xrefs ();
                    cfgCodeRef->set_target_type (mcsema::CodeReference::DataTarget);
                    cfgCodeRef->set_operand_type (mcsema::CodeReference::ImmediateOperand);
                    cfgCodeRef->set_location (mcsema::CodeReference::Internal);
                    cfgCodeRef->set_ea (a);

                    if (m_relocations.size () > 0)
                    {
                        auto entry = *(m_relocations.begin ());
                        for (auto ent : m_relocations)
                        {
                            if (ent.rel_addr () == (addr-instruction->size ())+1)
                            {
                                entry = ent;
                                break;
                            }
                        }

                        Offset off = entry.getDynSym ()->getOffset ();
                        cfgCodeRef->set_ea (off + entry.addend ());
                    }
                }
            }
        }
        else if (auto deref = dynamic_cast<InstructionAPI::Dereference *> (expr.get ()))
        {
            std::vector<InstructionAPI::InstructionAST::Ptr> children;
            deref->getChildren (children);
            auto expr = dynamic_cast<InstructionAPI::Expression *> (children [0].get ());
            if (!expr) throw std::runtime_error { "expected expression" };

            Address a;
            if (tryEval (expr, addr, a))
            {
                auto cfgCodeRef = cfgInstruction->add_xrefs ();
                cfgCodeRef->set_target_type (mcsema::CodeReference::DataTarget);
                cfgCodeRef->set_operand_type (mcsema::CodeReference::MemoryOperand);
                cfgCodeRef->set_location (mcsema::CodeReference::Internal);
                cfgCodeRef->set_ea (a);
            }
        }
    }
}

void CFGWriter::writeExternalFunctions ()
{
    for (const auto& func : m_extFuncMgr.getAllUsed ())
    {
        Address a;
        bool found = false;

        for (auto p : m_codeObj.cs ()->linkage ())
        {
            if (p.second == func.symbolName ())
            {
                found = true;
                a = p.first;
                break;
            }
        }

        if (!found)
            throw std::runtime_error { "unresolved external function call" };

        auto cfgExtFunc = m_module.add_external_funcs ();

        cfgExtFunc->set_name (func.symbolName ());
        cfgExtFunc->set_ea (a);
        cfgExtFunc->set_cc (func.cfgCallingConvention ());
        cfgExtFunc->set_has_return (func.hasReturn ());
        cfgExtFunc->set_no_return (func.noReturn ());
        cfgExtFunc->set_argument_count (func.argumentCount ());
        cfgExtFunc->set_is_weak (func.isWeak ());
    }
}

void CFGWriter::writeInternalData ()
{
    auto dataRegions = m_sectionMgr.getDataRegions ();

    for (auto region : dataRegions)
    {
        // Sanity check

        if (region->getMemSize () <= 0)
            continue;

        auto cfgInternalData = m_module.add_segments ();

        // Print raw data

        std::string data;
        int i = 0;

        for (; i < region->getDiskSize (); ++i)
            data += ((const char *) region->getPtrToRawData ()) [i];

        for (; i < region->getMemSize (); ++i)
            data += '\0';

        // Print metadata

        cfgInternalData->set_ea (region->getMemOffset ());
        cfgInternalData->set_data (data);
        cfgInternalData->set_read_only (region->getRegionPermissions () == SymtabAPI::Region::RP_R);
        cfgInternalData->set_is_external (false);
        cfgInternalData->set_name (region->getRegionName ());
        cfgInternalData->set_is_exported (true); /* TODO */
        cfgInternalData->set_is_thread_local (false); /* TODO */

        if (region->getRegionName () == ".got.plt")
        {
            const auto& relocations = region->getRelocations ();

            for (auto reloc : relocations)
            {
                for (auto f : m_codeObj.funcs ())
                {
                    if (f->entry ()->start () == reloc.getDynSym ()->getOffset ())
                    {
                        auto cfgSymbol = cfgInternalData->add_xrefs ();
                        cfgSymbol->set_ea (reloc.rel_addr ());
                        cfgSymbol->set_width (8);
                        cfgSymbol->set_target_ea (reloc.getDynSym ()->getOffset ());
                        cfgSymbol->set_target_name (f->name ());
                        cfgSymbol->set_target_is_code (true);

                        cfgSymbol->set_target_fixup_kind (mcsema::DataReference::Absolute);

                        break;
                    }
                }
            }
        }
    }
}

bool CFGWriter::isExternal (Address addr) const
{
    if (m_codeObj.cs ()->linkage ().find (addr) != m_codeObj.cs ()->linkage ().end ())
    {
        return m_extFuncMgr.isExternal (m_codeObj.cs ()->linkage () [addr]);
    }

    return false;
}

const std::string& CFGWriter::getExternalName (Address addr) const
{
    return m_codeObj.cs ()->linkage ().at (addr);
}

bool CFGWriter::tryEval (InstructionAPI::Expression *expr,
                         const Address ip, Address& result) const
{
    if (expr->eval ().format () != "[empty]")
    {
        result = expr->eval ().convert<Address> ();
        return true;
    }

    if (auto bin = dynamic_cast<InstructionAPI::BinaryFunction *> (expr))
    {
        std::vector<InstructionAPI::InstructionAST::Ptr> args;
        bin->getChildren (args);

        Address left, right;

        if (tryEval (dynamic_cast<InstructionAPI::Expression *> (args [0].get ()), ip, left)
            && tryEval (dynamic_cast<InstructionAPI::Expression *> (args [1].get ()), ip, right))
        {
            if (bin->isAdd ())
            {
                result = left + right;
                return true;
            }
            else if (bin->isMultiply ())
            {
                result = left * right;
                return true;
            }

            return false;
        }
    }
    else if (auto reg = dynamic_cast<InstructionAPI::RegisterAST *> (expr))
    {
        if (reg->format () == "RIP")
        {
            result = ip;
            return true;
        }
    }

    return false;
}
