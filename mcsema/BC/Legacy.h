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

#ifndef MCSEMA_BC_LEGACY_H_
#define MCSEMA_BC_LEGACY_H_

#include <cstdint>

namespace llvm {
class Function;
}  // namespace llvm
namespace mcsema {
namespace legacy {

void DowngradeModule(void);

// Create a `mcsema_real_eip` annotation, and annotate every unannotated
// instruction with this new annotation.
void AnnotateInsts(llvm::Function *func, uint64_t pc);

// Propagate any instruction annotations.
void PropagateInstAnnotations(void);

}  // namespace legacy
}  // namespace mcsema

#endif  // MCSEMA_BC_LEGACY_H_
