#include "Util.h"

mcsema::CodeReference *AddCodeXref(mcsema::Instruction * instruction,
                 mcsema::CodeReference::TargetType tarTy,
                 mcsema::CodeReference_OperandType opTy,
                 mcsema::CodeReference_Location location,
                 Dyninst::Address addr,
                 const std::string &name) {

    auto xref = instruction->add_xrefs();
    xref->set_target_type(tarTy);
    xref->set_operand_type(opTy);
    xref->set_location(location);
    xref->set_ea(addr);
    if (!name.empty())
        xref->set_name(name);
    return xref;
}


std::unique_ptr<DisassContext> gDisassContext(new DisassContext);
