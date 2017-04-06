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

#include <cctype>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>

#include "generated/CFG.pb.h"  // Auto-generated.

#include "mcsema/Arch/Arch.h"
#include "mcsema/CFG/CFG.h"

#include "mcsema/CFG/Externals.h"

namespace mcsema {
namespace {

static std::string LiftedFunctionName(const Function &cfg_func) {
  std::stringstream ss;
  ss << "sub_" << std::hex << cfg_func.ea();
  if (cfg_func.has_name()) {
    ss << "_" << cfg_func.name();
  }
  return ss.str();
}

static std::string LiftedSegmentName(const Segment &cfg_segment) {
  std::stringstream ss;
  ss << "seg_" << std::hex << cfg_segment.ea();
  if (cfg_segment.has_name()) {
    ss << "_";
    for (auto c : cfg_segment.name()) {
      if (isalnum(c)) {
        ss << c;
      } else {
        ss << "_";
      }
    }
  }
  return ss.str();
}

static std::string LiftedVarName(const Variable &cfg_var) {
  std::stringstream ss;
  ss << "var_" << std::hex << cfg_var.ea() << "_" << cfg_var.name();
  return ss.str();
}

static std::string LiftedBlockName(const Block &cfg_block) {
  std::stringstream ss;
  ss << "block_" << std::hex << cfg_block.ea();
  return ss.str();
}

static std::string ExternalFuncName(const ExternalFunction &cfg_func) {
  std::stringstream ss;
  ss << "ext_" << std::hex << cfg_func.ea() << "_" << cfg_func.name();
  return ss.str();
}

// Find the segment containing the data at `ea`.
static const NativeSegment *FindSegment(const NativeModule *module,
                                        uint64_t ea) {
  auto seg_it = module->segments.lower_bound(ea);
  while (seg_it != module->segments.end()) {
    auto target_segment = seg_it->second;
    auto seg_end = target_segment->ea + target_segment->size;
    if (ea >= seg_end) {
      return nullptr;
    }
    if (target_segment->ea <= ea && ea < seg_end) {
      return target_segment;
    }
    ++seg_it;
  }
  return nullptr;
}

// Resolve `xref` to a location.
static void ResolveReference(const NativeModule *module, NativeXref *xref) {
  xref->var = nullptr;
  xref->func = nullptr;

  auto var_it = module->ea_to_var.find(xref->target_ea);
  if (var_it != module->ea_to_var.end()) {
    xref->var = var_it->second;
    return;
  }

  auto func_it = module->ea_to_func.find(xref->target_ea);
  if (func_it != module->ea_to_func.end()) {
    xref->func = func_it->second;
    return;
  }

  if (!xref->target_name.empty()) {
    auto var_name_it = module->name_to_extern_var.find(xref->target_name);
    if (var_name_it != module->name_to_extern_var.end()) {
      xref->var = var_name_it->second;
      return;
    }

    auto func_name_it = module->name_to_extern_func.find(xref->target_name);
    if (func_name_it != module->name_to_extern_func.end()) {
      xref->func = func_name_it->second;
      return;
    }
  }

  LOG_IF(FATAL, !xref->target_segment)
      << "Data cross reference at " << std::hex << xref->ea
      << " targeting " << xref->target_name << " at "
      << std::hex << xref->target_ea << " does not match any known "
      << "externals and is not containing within any data segments.";
}

// Take the `CodeReference` information from the CFG and resolve it into
// a `NativeXref`. We do a bunch of checking to see if the recorded info
// in the protobuf is sane, and sanity doesn't 100% matter, because we
// do best effort matching in here and above, so error checking is mostly
// about letting us know if we should investigate something in the Python
// side of things.
static void AddXref(NativeModule *module, NativeInstruction *inst,
                    const CodeReference &cfg_ref) {
  NativeXref xref = {};
  xref.ea = inst->ea;
  xref.segment = FindSegment(module, xref.ea);
  xref.target_ea = static_cast<uint64_t>(cfg_ref.address());
  xref.target_segment = FindSegment(module, xref.target_ea);
  if (cfg_ref.has_name()) {
    xref.target_name = cfg_ref.name();
  }

  const NativeXref *xref_ptr = nullptr;
  auto xref_it = module->code_xrefs.find(xref.target_ea);
  if (xref_it != module->code_xrefs.end()) {
    xref_ptr = xref_it->second;
    xref = *xref_ptr;
  } else {
    ResolveReference(module, &xref);
  }

  bool xref_is_external = false;
  bool xref_is_code = false;

  // Does the XREF think its target is external?
  if (xref.func) {
    xref_is_external = xref.func->is_external;
    xref_is_code = true;
  } else if (xref.var) {
    xref_is_external = xref.var->is_external;
  } else {
    LOG(WARNING)
        << "Reference from " << std::hex << inst->ea
        << " to " << std::hex << xref.target_ea
        << " targets the segment " << xref.segment->name
        << " but was not resolved to a real symbol.";
    xref_is_external = xref.segment->is_external;
  }

  // Does the CFG reference target type agree with the resolved code/data
  // nature of the xref?
  if (cfg_ref.target_type() == CodeReference_TargetType_CodeTarget) {
    LOG_IF(ERROR, nullptr == xref.func)
        << "Code cross-reference to " << std::hex << xref.target_ea
        << " from " << std::hex << inst->ea
        << " is not actually a code cross-reference";
  } else {
    LOG_IF(ERROR, nullptr != xref.func)
        << "Data cross-reference to " << std::hex << xref.target_ea
        << " from " << std::hex << inst->ea
        << " is actually a code cross-reference";
  }

  // Does the CFG reference target location agree with the resolved
  // externality of the xref?
  if (cfg_ref.location() == CodeReference_Location_External) {
    LOG_IF(ERROR, !xref_is_external)
        << "External reference from " << std::hex << inst->ea
        << " to " << std::hex << xref.target_ea << " is actually internal";
  } else {
    LOG_IF(ERROR, xref_is_external)
        << "Internal reference from " << std::hex << inst->ea
        << " to " << std::hex << xref.target_ea << " is actually external";
  }

  // Only record flow cross-references for externals. Really, all we care
  // about is short-circuiting calls through thunks into direct calls to
  // externals. All other flow types should really be statically known.
  if (cfg_ref.operand_type() == CodeReference_OperandType_ControlFlowOperand) {
    if (!xref_is_external || !xref_is_code) {
      return;
    }
  }

  if (!xref_ptr) {
    auto xref_alloc = new NativeXref;
    *xref_alloc = xref;
    xref_ptr = xref_alloc;
    module->code_xrefs[xref.target_ea] = xref_ptr;
  }

  switch (cfg_ref.operand_type()) {
    case CodeReference_OperandType_ImmediateOperand:
      inst->imm = xref_ptr;
      break;
    case CodeReference_OperandType_MemoryOperand:
      inst->mem = xref_ptr;
      break;
    case CodeReference_OperandType_MemoryDisplacementOperand:
      inst->disp = xref_ptr;
      break;
    case CodeReference_OperandType_ControlFlowOperand:
      inst->flow = xref_ptr;
      break;
  }
}

}  // namespace

// Convert the protobuf into an in-memory data structure. This does a fair
// amount of checking and tries to correct errors in favor of converting
// variables into functions, and internals into externals. The intuition is
// that, at least in ELF binaries, externals will usually have some kind of
// 'internal' location for the sake of linking, and so we want to dedup
// internals into externals whenever possible.
NativeModule *ReadProtoBuf(const std::string &file_name) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  std::ifstream fstream(file_name, std::ios::binary);
  CHECK(fstream.good())
      << "Unable to open CFG file " << file_name;

  Module cfg;
  CHECK(cfg.ParseFromIstream(&fstream))
      << "Unable to read module from CFG file " << file_name;

  LOG(INFO)
      << "Lifting program " << cfg.name() << " via CFG protobuf in "
      << file_name;

  auto module = new NativeModule;

  // Collect variables from within the data sections. We set up the segment
  // information by not their data. We leave that until later when all
  // cross-references have been resolved.
  for (const auto &cfg_segment : cfg.segments()) {
    auto segment = new NativeSegment;
    segment->ea = static_cast<uint64_t>(cfg_segment.ea());
    segment->size = cfg_segment.data().size();
    if (cfg_segment.has_name()) {
      segment->name = cfg_segment.name();
    }
    segment->lifted_name = LiftedSegmentName(cfg_segment);
    segment->is_read_only = cfg_segment.read_only();
    segment->is_external = cfg_segment.is_external();

    // Collect the variables.
    for (const auto &cfg_var : cfg_segment.vars()) {
      CHECK(!cfg_var.name().empty())
          << "Unnamed variable at " << std::hex << cfg_var.ea()
          << " in segment " << segment->name;

      auto var = new NativeVariable;
      var->ea = static_cast<uint64_t>(cfg_var.ea());
      var->name = cfg_var.name();
      var->is_external = false;
      var->lifted_name = LiftedVarName(cfg_var);
      var->segment = segment;

      auto ea_var_it = module->ea_to_var.find(var->ea);
      if (ea_var_it != module->ea_to_var.end()) {
        LOG(ERROR)
            << "Duplicate (non-external) variable at " << std::hex << var->ea
            << " in segment " << segment->name;
        delete ea_var_it->second;
      }
      module->ea_to_var[var->ea] = var;
    }

    // Note! These go in by the *end* of the segment, so that `std::lower_bound`
    // works!
    module->segments[segment->ea + segment->size] = segment;

    LOG(INFO)
        << "Added segment " << segment->name << " [" << std::hex << segment->ea
        << ", " << std::hex << (segment->ea + segment->size) << ")";
  }

  // Bring in the functions, although not their blocks or instructions. This
  // first step enables better cross-reference resolution when we deserialize
  // the instructions.
  module->ea_to_func.reserve(cfg.funcs_size());
  for (const auto &cfg_func : cfg.funcs()) {
    auto func = new NativeFunction;
    func->ea = static_cast<uint64_t>(cfg_func.ea());
    func->is_external = false;
    func->lifted_name = LiftedFunctionName(cfg_func);
    func->name = cfg_func.has_name() ? cfg_func.name() : func->lifted_name;
    func->blocks.reserve(cfg_func.blocks_size());

    auto func_it = module->ea_to_func.find(func->ea);
    if (func_it != module->ea_to_func.end()) {
      LOG(ERROR)
          << "Duplicate function at " << std::hex << func->ea;
      delete func_it->second;
    }

    module->ea_to_func[func->ea] = func;

    auto var_it = module->ea_to_var.find(func->ea);
    if (var_it != module->ea_to_var.end()) {
      auto dup_var = var_it->second;
      LOG(ERROR)
          << "Function " << func->name << " at " << std::hex << func->ea
          << " is also defined as an internal variable " << dup_var->name;
      module->ea_to_var.erase(var_it);
      module->exported_vars.erase(func->ea);
      delete dup_var;
    }

    if (cfg_func.is_entrypoint()) {
      CHECK(!func->name.empty())
          << "Exported function at address " << std::hex << func->ea
          << " does not have a name";

      LOG(INFO)
          << "Exported function " << func->name << " at " << std::hex
          << func->ea << " is implemented by " << func->lifted_name;
      module->exported_funcs.insert(func->ea);
    }
  }

  // Bring in the external variables.
  for (const auto &cfg_extern_var : cfg.external_vars()) {
    auto var = new NativeExternalVariable;
    var->ea = static_cast<uint64_t>(cfg_extern_var.ea());
    var->name = cfg_extern_var.name();
    var->is_external = true;
    var->lifted_name = var->name;
    var->is_weak = cfg_extern_var.is_weak();
    var->size = static_cast<uint64_t>(cfg_extern_var.size());

    CHECK(!var->name.empty())
        << "Unnamed external variable at " << std::hex << var->ea;

    CHECK(!module->ea_to_func.count(var->ea))
        << "Internal function at " << std::hex << var->ea
        << " is also the external variable " << var->name;

    auto extern_var_it = module->name_to_extern_var.find(var->name);
    if (extern_var_it != module->name_to_extern_var.end()) {
      auto dup_var = extern_var_it->second;

      if (dup_var->ea != var->ea) {
        LOG(ERROR)
            << "External variable " << var->name << " at " << std::hex
            << var->ea << " is also defined at " << dup_var->ea;
        module->ea_to_var[dup_var->ea] = var;
      } else {
        LOG(ERROR)
            << "External variable " << var->name << " at " << std::hex
            << var->ea << " has the same name of external variable at "
            << std::hex << dup_var->ea;
      }

      // Note:  Intentional leak, not doing `delete dup_var`. Could be solved
      //        using `std::shared_ptr`, but we never free the CFG anyway.
    }

    auto var_it = module->ea_to_var.find(var->ea);
    if (var_it != module->ea_to_var.end()) {
      auto dup_var = var_it->second;

      if (dup_var->name != var->name) {
        LOG(ERROR)
            << "External variable " << var->name << " at " << std::hex
            << var->ea << " is also defined as " << dup_var->name;
        module->name_to_extern_var[dup_var->name] = var;
      } else {
        LOG(ERROR)
            << "External variable " << var->name << " at " << std::hex
            << var->ea << " is defined twice";
      }

      // Note:  Intentional leak, not doing `delete dup_var`. Could be solved
      //        using `std::shared_ptr`, but we never free the CFG anyway.
    }

    module->ea_to_var[var->ea] = var;
    module->name_to_extern_var[var->name] = var;
  }

  // Bring in the external functions.
  //
  // TODO(pag): Handle calling conventions and stuff.
  for (const auto &cfg_extern_func : cfg.external_funcs()) {
    auto func = new NativeExternalFunction;
    func->name = cfg_extern_func.name();
    func->lifted_name = ExternalFuncName(cfg_extern_func);
    func->ea = static_cast<uint64_t>(cfg_extern_func.ea());
    func->is_external = true;

    CHECK(!func->name.empty())
        << "External function at " << std::hex << func->ea << " has no name.";

    CHECK(!module->ea_to_var.count(func->ea))
        << "Internal variable at " << std::hex << func->ea
        << " is also the external function " << func->name;

    LOG(INFO)
        << "Found external function " << func->name << " via "
        << std::hex << func->ea;

    // Check to see if this function has previously been marked as a variable.
    auto var_it = module->name_to_extern_var.find(func->name);
    if (var_it != module->name_to_extern_var.end()) {
      auto dup_var = var_it->second;
      if (dup_var->ea != func->ea) {
        LOG(ERROR)
            << "External variable at " << std::hex << dup_var->ea
            << " has the same name as the external function "
            << func->name << " at " << std::hex << func->ea;

        module->ea_to_func[dup_var->ea] = func;
      } else {
        LOG(ERROR)
            << "External variable at " << std::hex << dup_var->ea
            << " is actually an external function.";
      }

      module->ea_to_var.erase(dup_var->ea);
      module->name_to_extern_var.erase(var_it);

      // Note:  Intentional leak, not doing `delete dup_var`. Could be solved
      //        using `std::shared_ptr`, but we never free the CFG anyway.
    }

    // Check to see if an external function with the same name was already
    // added. This is possible if there are things like thunks calling thunks,
    // or thin wrappers around thunks.
    auto extern_func_it = module->name_to_extern_func.find(func->name);
    auto will_find_ea = false;
    if (extern_func_it != module->name_to_extern_func.end()) {
      auto dup_func = extern_func_it->second;
      LOG(ERROR)
          << "External function " << func->name << " at " << std::hex
          << func->ea << " has the same name of external function at "
          << std::hex << dup_func->ea;

      if (dup_func->ea != func->ea) {
        LOG(ERROR)
            << "External function " << func->name << " at " << std::hex
            << func->ea << " is also defined at " << std::hex << dup_func->ea;
        module->ea_to_func[dup_func->ea] = func;
        will_find_ea = true;

        // Note:  Intentional leak, not doing `delete dup_func`. Could be solved
        //        using `std::shared_ptr`, but we never free the CFG anyway.
      } else {
        LOG(ERROR)
            << "External function " << func->name << " at " << std::hex
            << func->ea << " is defined twice";
      }
    }

    auto func_it = module->ea_to_func.find(func->ea);
    if (func_it != module->ea_to_func.end()) {
      auto dup_func = func_it->second;
      if (dup_func->name != func->name) {
        LOG(ERROR)
            << "External function " << func->name << " at " << std::hex
            << func->ea << " is also defined as " << dup_func->name;
        module->name_to_extern_func[dup_func->name] = func;

        // Note:  Intentional leak, not doing `delete dup_func`. Could be solved
        //        using `std::shared_ptr`, but we never free the CFG anyway.
      } else if (!will_find_ea) {
        LOG(ERROR)
            << "External function " << func->name << " at " << std::hex
            << func->ea << " is defined twice";
      }
    }

    module->exported_funcs.erase(func->ea);
    module->name_to_extern_func[func->name] = func;
    module->ea_to_func[func->ea] = func;
  }

  // Fill in the cross-reference entries for each segment.
  for (const auto &cfg_segment : cfg.segments()) {
    auto ea = static_cast<uint64_t>(cfg_segment.ea());
    auto seg_end_ea = ea + cfg_segment.data().size();
    auto segment = module->segments[seg_end_ea];

    std::map<uint64_t, const NativeXref *> xrefs;
    for (const auto &cfg_xref : cfg_segment.xrefs()) {
      auto xref = new NativeXref;
      xref->ea = static_cast<uint64_t>(cfg_xref.ea());
      xref->segment = segment;
      xref->width = static_cast<uint64_t>(cfg_xref.width());
      xref->target_ea = static_cast<uint64_t>(cfg_xref.target_ea());
      xref->target_name = cfg_xref.target_name();
      xref->target_segment = FindSegment(module, xref->target_ea);
      ResolveReference(module, xref);
      segment->entries[xref->ea] = {
          xref->ea, (xref->ea + xref->width), xref, nullptr};
    }
  }

  // Fill in the blob data entries for each segment.
  for (const auto &cfg_segment : cfg.segments()) {
    auto ea = static_cast<uint64_t>(cfg_segment.ea());
    auto seg_end_ea = ea + cfg_segment.data().size();
    auto segment = module->segments[seg_end_ea];
    std::vector<NativeSegment::Entry> blobs;

    // Sentinel.
    segment->entries[seg_end_ea] = {seg_end_ea, seg_end_ea, nullptr, nullptr};

    for (const auto &xref_entry : segment->entries) {
      const auto &entry = xref_entry.second;

      if (ea < entry.ea) {
        auto pos = ea - segment->ea;
        auto size = entry.ea - ea;

        auto blob = new NativeBlob;
        blob->ea = ea;
        blob->data = cfg_segment.data().substr(pos, size);
        blobs.push_back(NativeSegment::Entry{ea, entry.ea, nullptr, blob});
      }

      ea = entry.next_ea;
      if (ea == seg_end_ea) {
        break;
      }

      CHECK(ea < seg_end_ea)
          << "Walked off end of segment " << segment->name;
    }

    segment->entries.erase(seg_end_ea);

    // Add the blobs into the partition.
    for (const auto &entry : blobs) {
      segment->entries[entry.ea] = entry;
    }

    // Verify the partitioning of this segment's data.
    ea = segment->ea;
    for (const auto &entry : segment->entries) {
      CHECK(entry.first == ea)
          << "Invalid partitioning of segment " << segment->name;

      CHECK(entry.second.ea == ea)
          << "Invalid partitioning of segment " << segment->name;

      CHECK(entry.second.next_ea > entry.second.ea)
          << "Invalid partitioning of segment " << segment->name;

      ea = entry.second.next_ea;
    }

    CHECK(ea == (segment->ea + segment->size))
        << "Invalid partitioning of segment " << segment->name;
  }


  // Add in each of the function's blocks. At this stage we have all cross-
  // reference information available.
  module->ea_to_func.reserve(cfg.funcs_size());
  for (const auto &cfg_func : cfg.funcs()) {
    auto func = const_cast<NativeFunction *>(
        module->ea_to_func[static_cast<uint64_t>(cfg_func.ea())]);

    for (const auto &cfg_block : cfg_func.blocks()) {
      auto block = new NativeBlock;
      block->ea = static_cast<uint64_t>(cfg_block.ea());
      block->lifted_name = LiftedBlockName(cfg_block);
      block->instructions.reserve(cfg_block.instructions_size());

      // Add in the addresses of the block's successors.
      for (auto succ_ea : cfg_block.successor_eas()) {
        block->successor_eas.insert(static_cast<uint64_t>(succ_ea));
      }

      // Add in the block's instructions.
      for (const auto &cfg_inst : cfg_block.instructions()) {
        auto inst = new NativeInstruction;
        inst->ea = static_cast<uint64_t>(cfg_inst.ea());
        inst->bytes = cfg_inst.bytes();
        inst->does_not_return = cfg_inst.has_local_noreturn();
        inst->imm = nullptr;
        inst->flow = nullptr;
        inst->mem = nullptr;
        inst->disp = nullptr;
        inst->offset_table = 0;

        for (const auto &cfg_ref : cfg_inst.xrefs()) {
          AddXref(module, inst, cfg_ref);
        }

        block->instructions.push_back(inst);
      }

      func->blocks[block->ea] = block;
    }

    // Validate the successor relationships of this block.
    for (const auto &cfg_block : cfg_func.blocks()) {
      for (auto succ_ea : cfg_block.successor_eas()) {
        auto ea = static_cast<uint64_t>(succ_ea);
        auto succ_is_block = 0 != func->blocks.count(ea);
        auto succ_is_func = module->ea_to_func.count(ea);

        LOG_IF(ERROR, !succ_is_block && !succ_is_func)
            << "Successor " << std::hex << ea << " of block "
            << std::hex << static_cast<uint64_t>(cfg_block.ea())
            << " in function " << static_cast<uint64_t>(cfg_func.ea())
            << " does not exist";
      }
    }
  }

  return module;
}

const NativeFunction *NativeModule::TryGetFunction(uint64_t ea) const {
  auto func_it = ea_to_func.find(ea);
  if (func_it == ea_to_func.end()) {
    return nullptr;
  }
  return func_it->second;
}

const NativeVariable *NativeModule::TryGetVariable(uint64_t ea) const {
  auto var_it = ea_to_var.find(ea);
  if (var_it == ea_to_var.end()) {
    return nullptr;
  }
  return var_it->second;

}

}  // namespace mcsema
