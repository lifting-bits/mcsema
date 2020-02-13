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

ws::Workspace FromProto(const std::string &from, const std::string &ws) {
  return ws::Workspace(ws);
}

} // namespace mcsema::init
