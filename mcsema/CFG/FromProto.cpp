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


struct ProtoWriter {

  ws::Module &_module;
  mcsema::Module &_proto;

  ProtoWriter(ws::Module &module, mcsema::Module &proto)
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

  void ExternalFunctions() {
    for (auto ext_func : _proto.external_funcs()) {
      _module.AddExternalFunction(
          ext_func.ea(),
          ToSymbol(ext_func.name()),
          CC(ext_func.cc()), ext_func.has_return(), ext_func.is_weak());
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
          ConvertFixupKind(d_xref.target_fixup_kind()),
          // TODO(lukas): It may make sense to have get_or_create here
          ToSymbol(d_xref.target_name())
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

      DataXrefs(s, ws_s);
    }
  }

  void Write() {
    ExternalFunctions();
    ExternalVariables();
    GlobalVariables();
    Segments();
  }
};


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
