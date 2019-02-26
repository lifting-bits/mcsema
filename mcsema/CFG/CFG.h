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

#ifndef MCSEMA_CFG_CFG_H_
#define MCSEMA_CFG_CFG_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <llvm/IR/CallingConv.h>

namespace llvm {
class Constant;
class GlobalVariable;
}  // namespace llvm
namespace mcsema {

struct NativeVariable;
struct NativeStackVariable;
struct NativeExceptionFrame;
struct NativeFunction;

struct NativeExternalVariable;
struct NativeExternalFunction;

struct NativeSegment;
struct NativeXref;

struct NativeInstruction {
  uint64_t ea = 0;
  uint64_t lp_ea = 0;
  std::string bytes;

  const NativeXref *flow = nullptr;
  const NativeXref *mem = nullptr;
  const NativeXref *imm = nullptr;
  const NativeXref *disp = nullptr;
  const NativeXref *offset_table = nullptr;

  const NativeStackVariable *stack_var = nullptr;

  bool does_not_return;
};

struct NativeBlock {
  uint64_t ea = 0;
  std::string lifted_name;
  std::vector<const NativeInstruction *> instructions;
  std::unordered_set<uint64_t> successor_eas;
};

// Generic object used in the binary. This includes both internally and
// externally defined. In practice, those externally defined objects still
// have meaningful and unique effective addresses, usually pointing to
// some kind of relocation section within the binary.
struct NativeObject {
  NativeObject(void);

  // Forwarding pointer to resolve duplicates and such.
  mutable NativeObject *forward;

  uint64_t ea = 0;
  std::string name;  // Name in the binary.
  std::string lifted_name;  // Name in the bitcode.

  bool is_external = false;
  bool is_exported = false;
  bool is_thread_local = false;

  void ForwardTo(NativeObject *dest) const;
  const NativeObject *Get(void) const;
  NativeObject *Get(void);
};

// Function that is defined inside the binary.
struct NativeFunction : public NativeObject {
  std::unordered_map<uint64_t, const NativeBlock *> blocks;
  std::vector<struct NativeStackVariable *> stack_vars;
  std::vector<struct NativeExceptionFrame *> eh_frame;
  mutable llvm::Function *function = nullptr;
  mutable llvm::Value *stack_ptr_var = nullptr;
  mutable llvm::Value *frame_ptr_var = nullptr;
};

struct NativeStackVariable : public NativeObject {
  uint64_t size = 0;
  int64_t offset = 0;
  std::unordered_map<uint64_t, int64_t> refs;
  mutable llvm::Value *llvm_var = nullptr;
};

struct NativeExceptionFrame : public NativeObject {
  uint64_t start_ea = 0;
  uint64_t end_ea = 0;
  uint64_t lp_ea = 0;
  uint64_t action_index = 0;
  mutable llvm::Value *lp_var = nullptr;
  std::unordered_map<uint64_t, NativeExternalVariable *> type_var;
};

// Function that is defined outside of the binary.
struct NativeExternalFunction : public NativeFunction {
  NativeExternalFunction(void);

  bool is_explicit = false;
  bool is_weak = false;
  unsigned num_args = 0;
  llvm::CallingConv::ID cc;
};

// Global variable defined inside of the lifted binary.
struct NativeVariable : public NativeObject {
  const NativeSegment *segment = nullptr;
  mutable llvm::Constant *address = nullptr;
};

// Global variable defined outside of the lifted binary.
struct NativeExternalVariable : public NativeVariable {
  uint64_t size = 0;
  bool is_weak;
};

// A cross-reference to something.
struct NativeXref {
  enum FixupKind {
    kAbsoluteFixup,
    kThreadLocalOffsetFixup
  };

  uint64_t width = 0;  // In bytes.
  uint64_t ea = 0;  // Location of the xref within its segment.
  uint64_t mask = 0;  // Bitmask to apply to this xref. Zero if none.
  const NativeSegment *segment = nullptr;  // Segment containing the xref.

  uint64_t target_ea = 0;
  std::string target_name;
  const NativeSegment *target_segment = nullptr;  // Target segment of the xref, if any.

  FixupKind fixup_kind;

  const NativeVariable *var = nullptr;
  const NativeFunction *func = nullptr;
};

struct NativeBlob {
  uint64_t ea = 0;
  std::string data;
};

struct NativeSegment : public NativeObject {
  struct Entry {
    Entry(void) = default;
    Entry(uint64_t, uint64_t, NativeXref *, NativeBlob *);

    uint64_t ea = 0;
    uint64_t next_ea = 0;
    const NativeXref *xref = nullptr;
    const NativeBlob *blob = nullptr;
  };

  uint64_t size = 0;
  bool is_read_only = false;

  // Partition of entries, which are either cross-references, or opaque
  // blobs of bytes. The ordering of entries is significant.
  std::map<uint64_t, Entry> entries;

  mutable bool needs_initializer = true;
  mutable llvm::GlobalVariable *seg_var = nullptr;
};

// NOTE(pag): Using an `std::map` (as opposed to an `std::unordered_map`) is
//            intentional so that we can get the ordering of `NativeSegment`s
//            by their `ea`s.
using SegmentMap = std::map<uint64_t, NativeSegment *>;

struct NativeModule {
  std::unordered_set<uint64_t> exported_vars;
  std::unordered_set<uint64_t> exported_funcs;

  SegmentMap segments;

  std::unordered_map<uint64_t, const NativeFunction *> ea_to_func;

  std::unordered_map<std::string, const NativeExternalFunction *>
      name_to_extern_func;

  // Represent global and external variables.
  std::unordered_map<uint64_t, const NativeVariable *> ea_to_var;
  std::unordered_map<std::string, const NativeExternalVariable *>
      name_to_extern_var;

  const NativeFunction *TryGetFunction(uint64_t ea) const;
  const NativeVariable *TryGetVariable(uint64_t ea) const;
};

NativeModule *ReadProtoBuf(const std::string &file_name,
                           uint64_t pointer_size);

}  // namespace mcsema

#endif  // MCSEMA_CFG_CFG_H_
