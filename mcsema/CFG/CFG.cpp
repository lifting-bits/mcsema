/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

#include <glog/logging.h>
#include <gflags/gflags.h>

#include <cctype>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>

#include <llvm/IR/Module.h>

// Auto-generated by cmake/protobuf inside the build directory.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#include <CFG.pb.h>
#pragma clang diagnostic pop
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/io/coded_stream.h>

#include "remill/Arch/Arch.h"
#include "remill/OS/OS.h"

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/External.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

DECLARE_bool(explicit_args);

namespace mcsema {
namespace {

static std::string SaneName(const std::string &name) {
  std::stringstream ss;
  if (!name.empty()) {
    for (auto c : name) {
      if (isalnum(c)) {
        ss << c;
      } else {
        ss << "_";
      }
    }
  }
  return ss.str();
}

static std::string LiftedFunctionName(const Function &cfg_func) {
  std::stringstream ss;
  ss << "sub_" << std::hex << cfg_func.ea();
  if (cfg_func.has_name()) {
    ss << "_" << SaneName(cfg_func.name());
  }
  return ss.str();
}

static std::string LiftedSegmentName(const Segment &cfg_segment) {
  std::stringstream ss;
  if (cfg_segment.has_variable_name()) {
    auto has_name = !cfg_segment.variable_name().empty();
    LOG_IF(ERROR, !has_name)
        << "CFG variable segment " << cfg_segment.name() << " at " << std::hex
        << cfg_segment.ea() << std::dec << " has an empty name.";

    if (has_name && cfg_segment.is_exported()) {
      ss << cfg_segment.variable_name();
    } else {
      ss << "seg_var_" << std::hex << cfg_segment.ea()
         << "_" << SaneName(cfg_segment.variable_name());
    }
  } else {
    ss << "seg_" << std::hex << cfg_segment.ea()
       << "_" << SaneName(cfg_segment.name());
  }
  return ss.str();
}

static std::string LiftedVarName(const Variable &cfg_var) {
  std::stringstream ss;
  ss << "var_" << std::hex << cfg_var.ea() << "_" << SaneName(cfg_var.name());
  return ss.str();
}

static std::string LiftedBlockName(const Block &cfg_block) {
  std::stringstream ss;
  ss << "block_" << std::hex << cfg_block.ea();
  return ss.str();
}

static std::string ExternalFuncName(const ExternalFunction &cfg_func) {
  std::stringstream ss;
  ss << "ext_" << std::hex << cfg_func.ea()
     << "_" << SaneName(cfg_func.name());
  return ss.str();
}

static std::string LiftedStackVariableName(const StackVariable &cfg_stack) {
  std::stringstream ss;
  ss << "sv_" << SaneName(cfg_stack.name());
  return ss.str();
}

// Find the segment containing the data at `ea`.
static const NativeSegment *FindSegment(const NativeModule *module,
                                        uint64_t ea) {
  for (const auto &entry : module->segments) {
    auto seg = entry.second;
    auto seg_end = seg->ea + seg->size;
    if (seg->ea <= ea && ea < seg_end) {
      return seg;
    }
  }
  return nullptr;
}

// Resolve `xref` to a location.
static bool ResolveReference(NativeModule *module, NativeXref *xref) {
  xref->var = nullptr;
  xref->func = nullptr;

  auto var_it = module->ea_to_var.find(xref->target_ea);
  if (var_it != module->ea_to_var.end()) {
    xref->var = reinterpret_cast<const NativeVariable *>(var_it->second->Get());
    return true;
  }

  auto func_it = module->ea_to_func.find(xref->target_ea);
  if (func_it != module->ea_to_func.end()) {
    xref->func = reinterpret_cast<const NativeFunction *>(
        func_it->second->Get());
    return true;
  }

  if (!xref->target_name.empty()) {
    auto var_name_it = module->name_to_extern_var.find(xref->target_name);
    if (var_name_it != module->name_to_extern_var.end()) {
      xref->var = reinterpret_cast<const NativeVariable *>(
          var_name_it->second->Get());
      return true;
    }

    auto func_name_it = module->name_to_extern_func.find(xref->target_name);
    if (func_name_it != module->name_to_extern_func.end()) {
      xref->func = reinterpret_cast<const NativeFunction *>(
          func_name_it->second->Get());
      return true;
    }
  }

  if (xref->target_segment) {
    return true;
  }

  // Try to recover by finding a local variable.
  for (const auto &entry : module->ea_to_var) {
    auto var = entry.second;
    if (var->name == xref->target_name) {
      auto final_var = reinterpret_cast<const NativeVariable *>(var->Get());
      xref->var = final_var;
      xref->target_segment = final_var->segment;
      module->ea_to_var[xref->target_ea] = final_var;

      LOG(ERROR)
          << "Attempting reference fix at " << std::hex << xref->ea
          << " targeting " << xref->target_name << " using variable "
          << std::hex << var->ea << ", resolving to variable "
          << final_var->name << " at " << std::hex << final_var->ea;
      return true;
    }
  }

  // Try to recover by finding a local variable.
  for (const auto &entry : module->ea_to_func) {
    auto func = entry.second;
    if (func->name == xref->target_name) {
      auto final_func = reinterpret_cast<const NativeFunction *>(func->Get());
      xref->func = final_func;
      module->ea_to_func[xref->target_ea] = final_func;

      LOG(ERROR)
          << "Attempting reference fix at " << std::hex << xref->ea
          << " targeting " << xref->target_name << " using variable "
          << std::hex << func->ea << ", resolving to function "
          << final_func->name << " at " << std::hex << final_func->ea;
      return true;
    }
  }

  if (xref->target_segment) {
    LOG(WARNING)
        << "Data cross reference at " << std::hex << xref->ea
        << " in segment " << xref->segment->name
        << " targeting " << xref->target_ea << " in segment "
        << xref->target_segment->name << " has no name.";
    return true;
  }

  if (xref->target_name.empty()) {
    LOG(ERROR)
        << "Data cross reference at " << std::hex << xref->ea
        << " targeting " << std::hex << xref->target_ea
        << " does not match any known externals and is not "
        << "contained within any data segments.";

  } else {
    LOG(ERROR)
        << "Data cross reference at " << std::hex << xref->ea
        << " targeting " << xref->target_name << " at "
        << std::hex << xref->target_ea << " does not match any known "
        << "externals and is not contained within any data segments.";
  }
  return false;
}

// Take the `CodeReference` information from the CFG and resolve it into
// a `NativeXref`. We do a bunch of checking to see if the recorded info
// in the protobuf is sane, and sanity doesn't 100% matter, because we
// do best effort matching in here and above, so error checking is mostly
// about letting us know if we should investigate something in the Python
// side of things.
static void AddXref(NativeModule *module, NativeInstruction *inst,
                    const CodeReference &cfg_ref, uint64_t pointer_size) {
  auto xref = new NativeXref;
  xref->ea = inst->ea;
  xref->mask = 0;
  xref->width = pointer_size;
  xref->segment = FindSegment(module, xref->ea);
  xref->target_ea = static_cast<uint64_t>(cfg_ref.ea());
  xref->target_segment = FindSegment(module, xref->target_ea);

  CHECK(xref->segment != nullptr)
      << "Could not identify segment containing cross-reference from "
      << std::hex << xref->ea << " to " << std::hex << xref->target_ea;

  if (cfg_ref.has_mask()) {
    xref->mask = static_cast<uint64_t>(cfg_ref.mask());
  }

  if (cfg_ref.has_name()) {
    xref->target_name = cfg_ref.name();
  }

  if (!ResolveReference(module, xref)) {
    delete xref;
    return;
  }

  bool xref_is_external = false;
  bool xref_is_code = false;

  // Does the XREF think its target is external?
  if (xref->func) {
    xref_is_external = xref->func->is_external;
    xref_is_code = true;

  } else if (xref->var) {
    xref_is_external = xref->var->is_external;

  // `mcsema-disass` does not recover external segments (e.g. `extern`), so
  // a cross-reference that targets a NULL segment is, in practice, an
  // external reference.
  } else if (!xref->target_segment) {
    LOG(WARNING)
        << "Reference from " << std::hex << inst->ea
        << " to " << xref->target_ea << std::dec
        << " targets an unrecovered segment not resolved to a real symbol.";

    xref_is_external = true;

  } else {
    LOG(WARNING)
        << "Reference from " << std::hex << inst->ea
        << " to " << xref->target_ea << std::dec
        << " targets the segment " << xref->target_segment->name
        << " but was not resolved to a named symbol.";
    xref_is_external = xref->segment->is_external ||
                       xref->target_segment->is_external;
  }

  CHECK(!xref_is_external || !xref->target_name.empty())
      << "External reference from " << std::hex << inst->ea
      << " to " << xref->target_ea << std::dec << " does not have a name!";

  // Does the CFG reference target type agree with the resolved code/data
  // nature of the xref?
  if (cfg_ref.target_type() == CodeReference_TargetType_CodeTarget) {
    LOG_IF(WARNING, nullptr == xref->func)
        << "Code cross-reference from " << std::hex << inst->ea
        << " to " << std::hex << xref->target_ea << std::dec
        << " is not actually a code cross-reference";
  } else {

    // NOTE(pag): This will come up a lot with the `.idata` section in PE
    //            binaries. We'll have things like:
    //
    //    .idata:1400110E8 ; void __stdcall EnterCriticalSection(...)
    //    .idata:1400110E8                 extrn EnterCriticalSection:qword
    //
    //            And so we'll only really have this one location to represent
    //            both the function `EnterCriticalSection`, and the pointer to
    //            the function (this is a bit like the `.got.plt` section of
    //            ELF binaries, but they have an addition `.extern` section).
    //            So we'll end up with code that does something like:
    //
    //    jmp cs:EnterCriticalSection
    //
    //            And we'll say it's got a data AND flow reference to
    //            `EnterCriticalSection`. But the data reference itself looks
    //            like it should be a code reference, because we implement this
    //            type of reference as (from a mcsema-disass log):
    //
    //    8-byte reference at 1400110e8 to 1400110e8 (EnterCriticalSection)
    //
    //            That is, it's self-referential. It's illogical for us to
    //            eventually lift the `cs:EnterCriticalSection` operand of this
    //            instruction as loading the bytes of the instruction itself,
    //            though.
    LOG_IF(WARNING, nullptr != xref->func)
        << "Data cross-reference from " << std::hex << inst->ea
        << " to " << xref->target_ea << std::dec
        << " is actually a code cross-reference";
  }

  // Does the CFG reference target location agree with the resolved
  // externality of the xref? This isn't an atypical error. It can come up
  // where ELF binaries will have a relocation like `stderr@GLIBC_XYZ`, and
  // that will be an element in the `.bss` wherein the actual pointer to
  // `stderr` will be placed.
  if (cfg_ref.location() == CodeReference_Location_External) {
    LOG_IF(WARNING, !xref_is_external)
        << "External reference from " << std::hex << inst->ea
        << " to " << xref->target_ea << std::dec << " is actually internal";
  } else {
    LOG_IF(WARNING, xref_is_external)
        << "Internal reference from " << std::hex << inst->ea
        << " to " << xref->target_ea << std::dec << " (" << xref->target_name
        << ") is actually external";
  }

  switch (cfg_ref.operand_type()) {
    case CodeReference_OperandType_ImmediateOperand:
      LOG_IF(ERROR, inst->imm != nullptr)
          << "Overwriting existing immediate reference at instruction "
          << std::hex << inst->ea << std::dec;
      inst->imm = xref;
      break;

    case CodeReference_OperandType_MemoryOperand:
      LOG_IF(ERROR, inst->mem != nullptr)
          << "Overwriting existing absolute reference at instruction "
          << std::hex << inst->ea << std::dec;
      inst->mem = xref;
      break;

    case CodeReference_OperandType_MemoryDisplacementOperand:
      LOG_IF(ERROR, inst->disp != nullptr)
          << "Overwriting existing displacement reference at instruction "
          << std::hex << inst->ea << std::dec;
      inst->disp = xref;
      break;

    case CodeReference_OperandType_ControlFlowOperand:
      LOG_IF(ERROR, inst->flow != nullptr)
          << "Overwriting existing flow reference at instruction "
          << std::hex << inst->ea << std::dec;
      inst->flow = xref;
      break;

    case CodeReference_OperandType_OffsetTable:
      LOG_IF(ERROR, inst->offset_table != nullptr)
          << "Overwriting existing offset table reference at instruction "
          << std::hex << inst->ea << std::dec;
      inst->offset_table = xref;
      break;
  }
}

}  // namespace

NativeObject::NativeObject(void)
    : forward(this) {}

NativeExternalFunction::NativeExternalFunction(void)
    : cc(gArch->DefaultCallingConv()) {}

NativeSegment::Entry::Entry(
    uint64_t o_ea, uint64_t o_next_ea, NativeXref *o_xref, NativeBlob *o_blob) :
  ea(o_ea), next_ea(o_next_ea), xref(o_xref), blob(o_blob) {}

void NativeObject::ForwardTo(NativeObject *dest) const {
  if (forward != this) {
    forward->ForwardTo(dest);
    forward = dest;
  } else {
    forward = dest->Get();
  }
}

const NativeObject *NativeObject::Get(void) const {
  if (forward != this) {
    forward = forward->Get();
  }
  return forward;
}

NativeObject *NativeObject::Get(void) {
  if (forward != this) {
    forward = forward->Get();
  }
  return forward;
}

static void MergeVariables(NativeVariable *var, const NativeVariable *old_var) {
  var->is_exported = var->is_exported || old_var->is_exported;
  var->is_thread_local = var->is_thread_local || old_var->is_thread_local;
}

// Convert the protobuf into an in-memory data structure. This does a fair
// amount of checking and tries to correct errors in favor of converting
// variables into functions, and internals into externals. The intuition is
// that, at least in ELF binaries, externals will usually have some kind of
// 'internal' location for the sake of linking, and so we want to dedup
// internals into externals whenever possible.
NativeModule *ReadProtoBuf(const std::string &file_name,
                           uint64_t pointer_size) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  std::ifstream fstream(file_name, std::ios::binary);
  CHECK(fstream.good())
      << "Unable to open CFG file " << file_name;

  google::protobuf::io::IstreamInputStream pstream(&fstream);
  google::protobuf::io::CodedInputStream cstream(&pstream);
  cstream.SetTotalBytesLimit(512 * 1024 * 1024, -1);
  Module cfg;
  CHECK(cfg.ParseFromCodedStream(&cstream))
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
    segment->is_exported = cfg_segment.is_exported();
    segment->is_thread_local = cfg_segment.is_thread_local();
    segment->seg_var = nullptr;

    // Collect the variables.
    for (const auto &cfg_var : cfg_segment.vars()) {
      CHECK(!cfg_var.name().empty())
          << "Unnamed variable at " << std::hex << cfg_var.ea() << std::dec
          << " in segment " << segment->name;

      auto var = new NativeVariable;
      var->ea = static_cast<uint64_t>(cfg_var.ea());
      var->name = cfg_var.name();
      var->lifted_name = LiftedVarName(cfg_var);
      var->segment = segment;

      auto ea_var_it = module->ea_to_var.find(var->ea);
      if (ea_var_it != module->ea_to_var.end()) {
        LOG(ERROR)
            << "Duplicate (non-external) variable at " << std::hex << var->ea
            << std::dec << " in segment " << segment->name;

        MergeVariables(var, ea_var_it->second);
        ea_var_it->second->ForwardTo(var);
      }
      module->ea_to_var[var->ea] = var;

      LOG(INFO)
          << "Found variable " << var->name << " at " << std::hex
          << var->ea << std::dec;
    }

    module->segments[segment->ea] = segment;

    LOG(INFO)
        << "Found segment " << segment->name << " [" << std::hex << segment->ea
        << ", " << (segment->ea + segment->size) << std::dec << ")";
  }

  // Bring in the functions, although not their blocks or instructions. This
  // first step enables better cross-reference resolution when we deserialize
  // the instructions.
  module->ea_to_func.reserve(static_cast<size_t>(cfg.funcs_size()));
  for (const auto &cfg_func : cfg.funcs()) {
    auto func = new NativeFunction;
    func->ea = static_cast<uint64_t>(cfg_func.ea());
    func->lifted_name = LiftedFunctionName(cfg_func);
    func->name = cfg_func.has_name() ? cfg_func.name() : func->lifted_name;
    func->blocks.reserve(static_cast<size_t>(cfg_func.blocks_size()));
    func->is_exported = cfg_func.is_entrypoint();

    auto func_it = module->ea_to_func.find(func->ea);
    if (func_it != module->ea_to_func.end()) {
      LOG(ERROR)
          << "Duplicate function at " << std::hex << func->ea << std::dec;
      delete func_it->second;
    }

    module->ea_to_func[func->ea] = func;

    LOG(INFO)
        << "Found function " << func->name << " at " << std::hex
        << func->ea << std::dec;

    auto var_it = module->ea_to_var.find(func->ea);
    if (var_it != module->ea_to_var.end()) {
      auto dup_var = var_it->second;
      LOG(ERROR)
          << "Function " << func->name << " at " << std::hex << func->ea
          << std::dec << " is also defined as an internal variable "
          << dup_var->name;
      module->ea_to_var.erase(var_it);
      module->exported_vars.erase(func->ea);
      delete dup_var;
    }

    if (func->is_exported) {
      CHECK(!func->name.empty())
          << "Exported function at address " << std::hex << func->ea << std::dec
          << " does not have a name";

      LOG(INFO)
          << "Exported function " << func->name << " at " << std::hex
          << func->ea << std::dec << " is implemented by " << func->lifted_name;

      module->exported_funcs.insert(func->ea);
    }
  }

  // Bring in the external variables.
  for (const auto &cfg_extern_var : cfg.external_vars()) {
    auto var = new NativeExternalVariable;
    var->ea = static_cast<uint64_t>(cfg_extern_var.ea());
    var->name = cfg_extern_var.name();
    var->is_external = true;
    var->is_exported = true;
    var->is_thread_local = cfg_extern_var.is_thread_local();
    var->lifted_name = var->name;
    var->is_weak = cfg_extern_var.is_weak();
    var->size = static_cast<uint64_t>(cfg_extern_var.size());

    LOG(INFO)
        << "Found external variable " << var->name << " at "
        << std::hex << var->ea << std::dec;

    CHECK(!var->name.empty())
        << "Unnamed external variable at " << std::hex << var->ea << std::dec;

    CHECK(!module->ea_to_func.count(var->ea))
        << "Internal function at " << std::hex << var->ea << std::dec
        << " has the same name as the external variable " << var->name;

    // Look for two extern variables with the same name.
    auto extern_var_it = module->name_to_extern_var.find(var->name);
    if (extern_var_it != module->name_to_extern_var.end()) {
      auto dup_var = extern_var_it->second;
      MergeVariables(var, dup_var);
      dup_var->ForwardTo(var);

      if (dup_var->ea != var->ea) {
        LOG(WARNING)
            << "External variable " << var->name << " at " << std::hex
            << var->ea << " is also defined at " << dup_var->ea << std::dec;
        module->ea_to_var[dup_var->ea] = var;
      } else {
        LOG(ERROR)
            << "External variable " << var->name << " at " << std::hex
            << var->ea << " has the same name of external variable at "
            << dup_var->ea << std::dec;
      }
    }

    // Look for two variables with the same address.
    auto var_it = module->ea_to_var.find(var->ea);
    if (var_it != module->ea_to_var.end()) {
      auto dup_var = var_it->second;
      MergeVariables(var, dup_var);
      dup_var->ForwardTo(var);

      if (dup_var->name != var->name) {
        LOG(ERROR)
            << "External variable " << var->name << " at " << std::hex
            << var->ea << std::dec << " is also defined as " << dup_var->name;
        module->name_to_extern_var[dup_var->name] = var;
      } else {
        LOG(ERROR)
            << "External variable " << var->name << " at " << std::hex
            << var->ea << std::dec << " is defined twice";
      }

      // Note:  Intentional leak, not doing `delete dup_var`. Could be solved
      //        using `std::shared_ptr`, but we never free the CFG anyway.
    }

    module->ea_to_var[var->ea] = var;
    module->name_to_extern_var[var->name] = var;
  }

  // Bring in the external functions.
  for (const auto &cfg_extern_func : cfg.external_funcs()) {
    auto func = new NativeExternalFunction;
    func->name = cfg_extern_func.name();
    func->ea = static_cast<uint64_t>(cfg_extern_func.ea());
    func->is_external = true;
    func->is_exported = true;
    func->is_explicit = FLAGS_explicit_args || nullptr != gModule->getFunction(func->name);
    func->is_weak = cfg_extern_func.is_weak();
    func->lifted_name = ExternalFuncName(cfg_extern_func);
    func->num_args = 0;
    func->cc = gArch->DefaultCallingConv();

    LOG(INFO)
        << "Found external function " << func->name << " at "
        << std::hex << func->ea << std::dec;

    if (cfg_extern_func.has_argument_count()) {
      func->num_args = static_cast<unsigned>(cfg_extern_func.argument_count());
    }

    bool is_windows = remill::kOSWindows == gArch->os_name;

    // Most calling convention stuff is actually only meaningful for 32-bit,
    // x86 code. McSema was originally designed for 32-bit X86, so there needed
    // to be a way to distinguish between the various calling conventions used,
    // and so each function was given a specific one. But then 64-bit support
    // came along and now we're in a bad place where the calling convention is
    // specified, but only in a way that is relevant to 32-bit x86, so we need
    // to ignore it in some places and not others.
    if (gArch->IsX86()) {
      switch (cfg_extern_func.cc()) {
        case ExternalFunction_CallingConvention_CalleeCleanup:
          func->cc = llvm::CallingConv::X86_StdCall;
          break;

        case ExternalFunction_CallingConvention_FastCall:
          func->cc = llvm::CallingConv::X86_FastCall;
          break;

        case ExternalFunction_CallingConvention_CallerCleanup:  // cdecl.
          func->cc = llvm::CallingConv::C;
          break;

        default:
          if (is_windows) {
            func->cc = llvm::CallingConv::X86_StdCall;
          }
          break;
      }

    } else if (gArch->IsAMD64()) {
      if (is_windows) {
        func->cc = llvm::CallingConv::Win64;
      } else {
        func->cc = llvm::CallingConv::X86_64_SysV;
      }
    }

    CHECK(!func->name.empty())
        << "External function at " << std::hex << func->ea << " has no name.";

    LOG_IF(ERROR, module->ea_to_var.count(func->ea))
        << "Internal variable at " << std::hex << func->ea
        << " has the same name as the external function " << func->name;

    LOG(INFO)
        << "Found external function " << func->name << " via "
        << std::hex << func->ea;

    // Check to see if this function has previously been marked as a variable.
    auto var_it = module->name_to_extern_var.find(func->name);
    if (var_it != module->name_to_extern_var.end()) {
      auto dup_var = var_it->second;
      dup_var->ForwardTo(func);

      if (dup_var->ea != func->ea) {
        LOG(ERROR)
            << "External variable at " << std::hex << dup_var->ea
            << " has the same name as the external function "
            << func->name << " at " << std::hex << func->ea;

        module->ea_to_func[dup_var->ea] = func;
      } else {
        LOG(WARNING)
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
      dup_func->ForwardTo(func);

      if (dup_func->ea != func->ea) {
        LOG(WARNING)
            << "External function " << func->name << " at " << std::hex
            << func->ea << " is also defined at " << std::hex << dup_func->ea;

        module->ea_to_func[dup_func->ea] = func;
        will_find_ea = true;

      } else {
        LOG(ERROR)
            << "External function " << func->name << " at " << std::hex
            << func->ea << " is defined twice (by address)";
      }
    }

    auto func_it = module->ea_to_func.find(func->ea);
    if (func_it != module->ea_to_func.end()) {
      auto dup_func = func_it->second;
      dup_func->ForwardTo(func);

      if (dup_func->name != func->name) {
        LOG(ERROR)
            << "External function " << func->name << " at " << std::hex
            << func->ea << " is also defined as " << dup_func->name;
        module->name_to_extern_func[dup_func->name] = func;

      } else if (!will_find_ea) {
        LOG(ERROR)
            << "External function " << func->name << " at " << std::hex
            << func->ea << " is defined twice (by name)";
      }
    }

    module->exported_funcs.erase(func->ea);
    module->name_to_extern_func[func->name] = func;
    module->ea_to_func[func->ea] = func;
  }

  // Fill in the cross-reference entries for each segment.
  for (const auto &cfg_segment : cfg.segments()) {
    auto ea = static_cast<uint64_t>(cfg_segment.ea());
    auto segment = module->segments[ea];

    std::map<uint64_t, const NativeXref *> xrefs;
    for (const auto &cfg_xref : cfg_segment.xrefs()) {
      auto xref = new NativeXref;
      xref->ea = static_cast<uint64_t>(cfg_xref.ea());
      xref->segment = segment;
      xref->width = static_cast<uint64_t>(cfg_xref.width());
      xref->target_ea = static_cast<uint64_t>(cfg_xref.target_ea());
      xref->target_name = cfg_xref.target_name();
      xref->target_segment = FindSegment(module, xref->target_ea);

      CHECK(xref->width <= pointer_size)
          << "Cross reference at " << std::hex << xref->ea << " to "
          << xref->target_name << " at " << std::hex << xref->target_ea
          << " is too wide at " << xref->width << " bytes";

      switch (cfg_xref.target_fixup_kind()) {
        case DataReference_TargetFixupKind_Absolute:
          xref->fixup_kind = NativeXref::kAbsoluteFixup;
          break;
        case DataReference_TargetFixupKind_OffsetFromThreadBase:
          xref->fixup_kind = NativeXref::kThreadLocalOffsetFixup;
          break;
      }

      if (!ResolveReference(module, xref)) {
        delete xref;
        continue;
      }

      segment->entries[xref->ea] = {
          xref->ea, (xref->ea + xref->width), xref, nullptr};
    }
  }

  // Fill in the blob data entries for each segment.
  for (const auto &cfg_segment : cfg.segments()) {
    auto ea = static_cast<uint64_t>(cfg_segment.ea());
    auto segment = module->segments[ea];
    std::vector<NativeSegment::Entry> blobs;

    // Sentinel.
    auto seg_end_ea = ea + segment->size;
    segment->entries[seg_end_ea] = {seg_end_ea, seg_end_ea, nullptr, nullptr};

    for (const auto &xref_entry : segment->entries) {
      const auto &entry = xref_entry.second;

      // Split this segment's data up into logical components based on the
      // variables indexing into this segment.
      while (ea < entry.ea) {
        if (ea == seg_end_ea) {
          break;
        }

        auto pos = ea - segment->ea;

        // Find the beginning of the next variable or entry.
        uint64_t size = 1;
        for (; (ea + size) < entry.ea; ++size) {
          if (module->ea_to_var.count(ea + size)) {
            break;
          }
        }

        auto blob = new NativeBlob;
        blob->ea = ea;
        blob->data = cfg_segment.data().substr(pos, size);
        blobs.push_back(NativeSegment::Entry{ea, ea + size, nullptr, blob});
        ea += size;
      }

      CHECK(ea == entry.ea)
          << "Invalid partitioning of data before " << std::hex << entry.ea;

      if (ea == seg_end_ea) {
        break;
      }

      // Do some sanity checking to see if there are any variables pointing
      // into some actual cross-references. This is more strange than anything.
      for (ea += 1; ea < entry.next_ea; ++ea) {
        auto var_it = module->ea_to_var.find(ea);
        LOG_IF(ERROR, var_it != module->ea_to_var.end())
            << "Variable " << var_it->second->name << " at "
            << std::hex << var_it->second->ea
            << " points into a cross reference, located at " << std::hex
            << entry.xref->ea << " and targeting " << std::hex
            << entry.xref->target_ea;
      }
    }

    segment->entries.erase(seg_end_ea);

    // Add the blobs into the partition.
    for (const auto &entry : blobs) {
      segment->entries[entry.ea] = entry;
    }

    // Verify the partitioning of this segment's data.
    ea = segment->ea;
    unsigned entry_num = 0;
    for (const auto &entry : segment->entries) {
      CHECK(entry.first == ea)
          << "Invalid partitioning of segment " << segment->name
          << "; entry #" << std::dec << entry_num << " EA address "
          << std::hex << entry.first << " does not match "
          << "up with expected entry EA " << std::hex << ea;

      CHECK(entry.second.ea == ea)
          << "Invalid partitioning of segment " << segment->name;

      CHECK(entry.second.next_ea > entry.second.ea)
          << "Invalid partitioning of segment " << segment->name;

      ea = entry.second.next_ea;
      entry_num++;
    }

    CHECK(ea == (segment->ea + segment->size))
        << "Invalid partitioning of segment " << segment->name;
  }

  // Add in each of the function's blocks. At this stage we have all cross-
  // reference information available.
  module->ea_to_func.reserve(static_cast<size_t>(cfg.funcs_size()));
  for (const auto &cfg_func : cfg.funcs()) {
    auto func = const_cast<NativeFunction *>(
        module->ea_to_func[static_cast<uint64_t>(cfg_func.ea())]);

    // Extract the stack variables associated with the function
    for (const auto &stack_var : cfg_func.stack_vars()) {
      auto nat_sv = new NativeStackVariable;

      nat_sv->offset = stack_var.sp_offset();
      nat_sv->size = stack_var.size();
      nat_sv->ea = 0;
      nat_sv->name = stack_var.name();
      nat_sv->lifted_name = LiftedStackVariableName(stack_var);
      nat_sv->llvm_var = nullptr;
      func->stack_vars.push_back(nat_sv);

      for(auto ref_ea : stack_var.ref_eas()){
        nat_sv->refs[ref_ea.inst_ea()] = ref_ea.offset();
        LOG(INFO) << "Retrive the ref ea : " << std::hex
            << ref_ea.inst_ea() << std::dec << " offset " << ref_ea.offset();
      }
    }

    // Extract the eh_frame entries associated with the function
    for (const auto &entry : cfg_func.eh_frame()) {
      auto frame_var = new NativeExceptionFrame;

      frame_var->start_ea = entry.start_ea();
      frame_var->end_ea = entry.end_ea();
      frame_var->lp_ea = entry.lp_ea();
      frame_var->action_index = entry.action();

      // List all the types of the landing pad
      for (const auto &extern_var : entry.ttype()) {
        auto var = new NativeExternalVariable;
        var->ea = static_cast<uint64_t>(extern_var.ea());
        var->name = extern_var.name();
        var->is_external = true;
        var->is_exported = true;
        var->is_thread_local = extern_var.is_thread_local();
        var->lifted_name = var->name;
        var->is_weak = extern_var.is_weak();
        var->size = static_cast<uint64_t>(extern_var.size());
        frame_var->type_var[static_cast<uint64_t>(extern_var.size())] = var;
       }

      func->eh_frame.push_back(frame_var);
    }

    for (const auto &cfg_block : cfg_func.blocks()) {
      auto block = new NativeBlock;
      block->ea = static_cast<uint64_t>(cfg_block.ea());
      block->lifted_name = LiftedBlockName(cfg_block);
      block->instructions.reserve(
          static_cast<size_t>(cfg_block.instructions_size()));

      // Add in the addresses of the block's successors.
      for (auto succ_ea : cfg_block.successor_eas()) {
        block->successor_eas.insert(static_cast<uint64_t>(succ_ea));
      }

      // Add in the block's instructions.
      for (const auto &cfg_inst : cfg_block.instructions()) {
        auto inst = new NativeInstruction;
        inst->ea = static_cast<uint64_t>(cfg_inst.ea());
        inst->lp_ea = static_cast<uint64_t>(cfg_inst.lp_ea());
        inst->bytes = cfg_inst.bytes();
        inst->does_not_return = cfg_inst.has_local_noreturn();
        inst->imm = nullptr;
        inst->flow = nullptr;
        inst->mem = nullptr;
        inst->disp = nullptr;
        inst->offset_table = nullptr;
        inst->stack_var = nullptr;

        for (const auto &cfg_ref : cfg_inst.xrefs()) {
          AddXref(module, inst, cfg_ref, pointer_size);
        }

        for (const auto &var : func->stack_vars) {
          for (auto ref : var->refs) {
            if (inst->ea == ref.first) {
              LOG(INFO) << "The stack variable references at : " << std::hex << inst->ea;
              inst->stack_var = var;
            }
          }
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
  return reinterpret_cast<const NativeFunction *>(func_it->second->Get());
}

const NativeVariable *NativeModule::TryGetVariable(uint64_t ea) const {
  auto var_it = ea_to_var.find(ea);
  if (var_it == ea_to_var.end()) {
    return nullptr;
  }
  return reinterpret_cast<const NativeVariable *>(var_it->second->Get());
}

}  // namespace mcsema
