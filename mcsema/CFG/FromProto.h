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
#pragma once

#include "mcsema/CFG/WS.h"

#include <string>

namespace mcsema::cfg {

  // Add information from protobuf `from` to already existing workspace `ws`.
  // Returns `true` if anything was added to the workspace.
  bool Enhance(const std::string &from, ws::Workspace &ws);

  // Add information from protobuf `from` to already existing module `module`.
  // If protobuf contains information that collides with one already in `module`,
  // behaviour is undefined.
  // TODO(lukas): Resolve colisions.
  void Enhance(const std::string &from, ws::Module &module);

  // Transcribes protobuf in file `from` into new workspace `ws`.
  // If `ws` already contains Module contained in `from`, `ws` is not modified.
  ws::Workspace FromProto(const std::string &from, const std::string &ws);

} // namespace mcsema::init
