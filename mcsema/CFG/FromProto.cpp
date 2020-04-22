/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

#include "mcsema/CFG/FromProto.h"

#include <CFG.pb.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/io/coded_stream.h>

#include <fstream>
#include <unordered_map>

namespace mcsema::cfg {

// TODO: Move out to some util, is shared with mcsema/CFG.cpp
mcsema::Module LoadProto(const std::string &filename) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  std::ifstream fstream(filename, std::ios::binary);

  google::protobuf::io::IstreamInputStream pstream(&fstream);
  google::protobuf::io::CodedInputStream cstream(&pstream);
  cstream.SetTotalBytesLimit(512 * 1024 * 1024, -1 );

  mcsema::Module cfg;
  if (!cfg.ParseFromCodedStream(&cstream)) {
    assert(false);
  }
  return cfg;
}


struct Default {
  constexpr static const std::string_view code_section_name = ".text";
};


template<typename Configuration>
struct ProtoWriter_impl : Configuration {

  using Configuration::code_section_name;

  ws::Module &_module;
  mcsema::Module &_proto;

  // ws::MemoryRange does not have default ctor
  // Since ws::BasicBlock needs to be associated with memory range and memory ranges are
  // inserted before + information about their name is forgotten, it helps to remember
  // handle to the code section.
  std::optional<ws::MemoryRange> code_mem_range;

  template<typename Target>
  using ea_map = std::unordered_map<uint64_t, Target>;

  ea_map<ws::BasicBlock> ea_to_bb;
  ea_map<uint64_t> successor_relation;

  ProtoWriter_impl(ws::Module &module, mcsema::Module &proto)
    : _module(module), _proto(proto)
  {}

  ws::SymbolTableEntry ToSymbol(const std::string &name) {
    // Note(lukas): In protobuf there no way to know visibility
    return _module.AddSymbolTableEntry(name, ws::SymbolVisibility::Artificial);
  }

  ws::FixupKind ConvertFixupKind(mcsema::DataReference::TargetFixupKind kind) {
    switch(kind) {
      case DataReference_TargetFixupKind_Absolute:
        return ws::FixupKind::Absolute;
      case DataReference_TargetFixupKind_OffsetFromThreadBase:
        return ws::FixupKind::OffsetFromThreadBase;
    }
  }

  // FIXME: In mcsema it depends on arch
  ws::CallingConv CC(mcsema::ExternalFunction::CallingConvention cc) {
    switch(cc) {
      case ExternalFunction_CallingConvention_CalleeCleanup:
        return ws::CallingConv::X86_StdCall;
      case ExternalFunction_CallingConvention_FastCall:
        return ws::CallingConv::X86_FastCall;
      case ExternalFunction_CallingConvention_CallerCleanup:
        return ws::CallingConv::X86_StdCall;
    }
  }

  ws::CallingConv CC(mcsema::CallingConvention cc) {
    switch(cc) {
      case C:
      case X86_StdCall:
        return ws::CallingConv::X86_StdCall;
      case X86_FastCall:
        return ws::CallingConv::X86_FastCall;
      case X86_ThisCall:
        return ws::CallingConv::X86_ThisCall;
      case X86_64_SysV:
        return ws::CallingConv::X86_64_SysV;
      case Win64:
        return ws::CallingConv::Win64;
      case X86_VectorCall:
        return ws::CallingConv::X86_VectorCall;
      case X86_RegCall:
        return ws::CallingConv::X86_RegCall;
      case AArch64_VectorCall:
        return ws::CallingConv::AArch64_VectorCall;
    }
  }

  ws::OperandType ConvertOperandType(mcsema::CodeReference::OperandType op_type) {
    switch(op_type) {
      case CodeReference_OperandType_ImmediateOperand:
        return ws::OperandType::Immediate;
      case CodeReference_OperandType_MemoryOperand:
        return ws::OperandType::Memory;
      case CodeReference_OperandType_MemoryDisplacementOperand:
        return ws::OperandType::MemoryDisplacement;
      case CodeReference_OperandType_ControlFlowOperand:
        return ws::OperandType::ControlFlow;
      case CodeReference_OperandType_OffsetTable:
        return ws::OperandType::OffsetTable;
    }
  }

  void ExternalFunctions() {
    for (auto ext_func : _proto.external_funcs()) {
      auto func = _module.AddExternalFunction(
          static_cast<uint64_t>(ext_func.ea()),
          ToSymbol(ext_func.name()),
          CC(ext_func.cc()), ext_func.has_return(), ext_func.is_weak());
      func.SetFuncDecl(FuncDecl(ext_func.decl()));
    }
  }

  void ExternalVariables() {
    for (auto ext_v : _proto.external_vars()) {
      _module.AddExternalVar(
          static_cast<uint64_t>(ext_v.ea()),
          ext_v.name(),
          static_cast<uint64_t>(ext_v.size()),
          ext_v.is_weak(),
          ext_v.is_thread_local()
      );

    }
  }

  void GlobalVariables() {
    for (auto g_var : _proto.global_vars()) {
      _module.AddGlobalVar(
          static_cast<uint64_t>(g_var.ea()),
           g_var.name(),
           static_cast<uint64_t>(g_var.size())
      );
    }
  }

  template<typename Segment>
  ws::Segment SegmentMeta(const Segment &s, ws::MemoryRange &mem_r) {
    return mem_r.AddSegment(
        static_cast<uint64_t>(s.ea()),
        static_cast<uint64_t>(s.data().size()),
        { s.read_only(), s.is_external(), s.is_exported(), s.is_thread_local() },
        s.name()
    );
  }

  // Thrown away: target_is_code -> mcsema should be able to deduce it from target_ea
  template<typename Segment>
  void DataXrefs(const Segment &s, ws::Segment ws_s) {
    for (auto d_xref : s.xrefs()) {
      ws_s.AddXref(
          static_cast<uint64_t>(d_xref.ea()),
          static_cast<uint64_t>(d_xref.target_ea()),
          static_cast<uint64_t>(d_xref.width()),
          ConvertFixupKind(d_xref.target_fixup_kind())
      );
    }
  }

  // Thrown away: Segment::Variable
  void Segments() {
    for (auto s : _proto.segments()) {
      auto mem_r = _module.AddMemoryRange(
          static_cast<uint64_t>(s.ea()),
          s.data());

      auto ws_s = SegmentMeta(s, mem_r);

      if (s.name() == code_section_name) {
        code_mem_range = mem_r;
      }

      DataXrefs(s, ws_s);
    }
  }

  // Thrown away: location
  //              target_type
  template<typename BB>
  void CodeXref(BB &bb, ws::BasicBlock &ws_bb) {
    for (auto inst : bb.instructions()) {
      for (auto c_xref: inst.xrefs()) {
        ws_bb.AddXref(static_cast<uint64_t>(inst.ea()),
                      static_cast<uint64_t>(c_xref.ea()),
                      ConvertOperandType(c_xref.operand_type()));
      }
    }
  }


  template<typename BB>
  ws::BasicBlock GetBB(BB &bb) {
    auto ea = static_cast<uint64_t>(bb.ea());

    // TODO(lukas): What if `code_mem_range` is not set?
    auto [it, res] =
      ea_to_bb.try_emplace(ea, _module.AddBasicBlock(ea, {}, *code_mem_range));

    if (res)
      CodeXref(bb, it->second);
    return it->second;
  }

  template<typename BB>
  void SetSuccessors(BB &bb) {
    auto ws_bb = GetBB(bb);
    for (auto succ_ea : bb.successor_eas()) {
      auto [it, res] = successor_relation.try_emplace(static_cast<uint64_t>(bb.ea(),
                                                      static_cast<uint64_t>(succ_ea)));
      if (res) {
        ws_bb.AddSucc(ea_to_bb.at(static_cast<uint64_t>(succ_ea)));
      }
    }

  }

  template<typename F>
  void BBs(F &f, ws::Function &ws_f) {
    for (auto bb : f.blocks()) {
      auto ws_bb = GetBB(bb);
      ws_f.AttachBlock(ws_bb);
    }

    for (auto bb: f.blocks()) {
      SetSuccessors(bb);
    }
  }

  // Thrown away: StackVariables
  //              ExceptionFrames
  void Functions() {
    for (auto f: _proto.funcs()) {
      auto ws_f = _module.AddFunction(
          static_cast<uint64_t>(f.ea()),
          f.is_entrypoint()
      );
      ws_f.Name(ToSymbol(f.name()));

      BBs(f, ws_f);
    }
  }

  template<typename FD>
  ws::FuncDecl FuncDecl(const FD &fd) {
    using decls = ws::FuncDecl::ValueDecls;
    decls params;
    for (auto p : fd.parameters()) {
      params.push_back(ValueDecl(p));
    }

    decls rets;
    for (auto r : fd.return_values()) {
      rets.push_back(ValueDecl(r));
    }

    return _module.GetWS().AddFuncDecl(ValueDecl(fd.return_address()),
                                       ValueDecl(fd.return_stack_pointer()),
                                       params,
                                       rets,
                                       fd.is_variadic(), fd.is_noreturn(),
                                       CC(fd.calling_convention()));
  }

  template<typename VD>
  ws::ValueDecl ValueDecl(const VD &vd) {
    return _module.GetWS().AddValueDecl(
          vd.type(),
          (vd.has_register_() ? vd.register_() : std::optional<std::string>()),
          (vd.has_name() ? vd.name() : std::optional<std::string>()),
          (vd.has_memory() ? MemoryLoc(vd.memory()) : std::optional<ws::MemoryLocation>())
        );
  }

  template<typename ML>
  ws::MemoryLocation MemoryLoc(const ML &ml) {
    if (ml.has_offset()) {
      return _module.GetWS().AddMemoryLoc(ml.register_(), ml.offset());
    }
    return _module.GetWS().AddMemoryLoc(ml.register_());
  }

  void Write() {
    ExternalFunctions();
    ExternalVariables();
    GlobalVariables();
    Segments();
    Functions();
  }
};

using ProtoWriter = ProtoWriter_impl<Default>;

ws::Workspace FromProto(const std::string &from, const std::string &ws_name) {
  auto ws = ws::Workspace(ws_name);

  ws.CreateSchema();

  Enhance(from, ws);
  return ws;
}

bool Enhance(const std::string &from, ws::Workspace &ws) {
  auto proto = LoadProto(from);

  if (ws.GetModule(proto.name()))
    return false;

  auto ws_module = ws.AddModule(proto.name());
  ProtoWriter(ws_module, proto).Write();
  return true;
}

void Enhance(const std::string &from, ws::Module &module) {
  auto proto = LoadProto(from);
  ProtoWriter(module, proto).Write();
}



} // namespace mcsema::init
