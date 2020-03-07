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

#include <mcsema/BC/Info.h>
#include <mcsema/BC/Util.h>

#include <remill/BC/Util.h>

// TODO(lukas): Nested declaration once C++17 is available
namespace mcsema {
namespace info {

void Set(const Info &meta, llvm::Function &func) {
  SetMetadata(func, Kinds::ea_kind, std::to_string(meta.ea));
  SetMetadata(func, Kinds::name_kind, meta.name);
}

Info Get(llvm::Function &func) {
  return { Name(func), EA(func) };
}

std::string Name(llvm::Function &func) {
  return GetMetadata(func, Kinds::name_kind);
}

uint64_t EA(llvm::Function &func) {
  auto as_str = GetMetadata(func, Kinds::ea_kind);
  if (as_str.empty()) {
    LOG(WARNING) << remill::LLVMThingToString(&func) << " does not have set "
                 << Kinds::ea_kind;
    return 0xffffffff;
  }
  return stoul( as_str );
}

} // namespace info
} // namespace mcsema


