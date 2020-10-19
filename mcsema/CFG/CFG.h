/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <anvill/Program.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/IR/CallingConv.h>

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace llvm {
class Constant;
class Function;
class FunctionType;
class GlobalVariable;
}  // namespace llvm
namespace mcsema {

struct NativeVariable;
struct NativeStackVariable;
struct NativeExceptionFrame;
struct NativeExternalVariable;
struct NativeExternalFunction;
struct NativeFunction;
struct NativeModule;
struct NativeSegment;
struct NativeXref;

struct NativePreservedRegisters {
  llvm::SmallVector<std::string, 16> reg_names;
};

// A cross reference (xref) from an instruction to something.
struct NativeInstructionXref {
 public:
  // Target ea of the xref.
  uint64_t target_ea{0};

  // Bitmask to apply to this xref. Zero if none.
  uint64_t mask{0};
};

struct NativeInstruction {
  uint64_t ea{0};
  uint64_t lp_ea{0};

  const NativeInstructionXref *flow{nullptr};
  const NativeInstructionXref *mem{nullptr};
  const NativeInstructionXref *imm{nullptr};
  const NativeInstructionXref *disp{nullptr};
  const NativeInstructionXref *offset_table{nullptr};
};

struct NativeBlock {
  uint64_t ea{0};
  uint64_t last_inst_ea{0};
  llvm::SmallVector<uint64_t, 2> successor_eas;
  bool is_referenced_by_data{false};
};

// Generic object used in the binary. This includes both internally and
// externally defined. In practice, those externally defined objects still
// have meaningful and unique effective addresses, usually pointing to
// some kind of relocation section within the binary.
struct NativeObject {
  explicit NativeObject(NativeModule *module_);
  virtual ~NativeObject(void) = default;

  // Module containing this object.
  NativeModule *const module;

  // Forwarding pointer to resolve duplicates and such.
  mutable NativeObject *forward;

  uint64_t ea{0};

  // Some segments don't begin on page boundaries, and so we often add
  // padding bytes to the beginning of the LLVM global variable that
  // represents the segment to fill its size out so that we can page-align
  // the segment. This is important on fixed-width architectures like AArch64
  // because often two instructions are used to compute an address: one
  // instruction for the high bits, and another for the low bits. Often, the
  // instruction used for the low bits is an OR instruction. This means that
  // the original low N bits of a given effective address, and the lifted low
  // N bits corresponding to logically the same object, must match, else some
  // bits might be "lost". If ADDs were always used then this wouldn't be
  // a problem, but such is life.
  uint64_t padding{0};

  mutable std::string name;  // Name in the binary.
  std::string lifted_name;  // Name in the bitcode.

  // TODO(pag): Rework all these booleans into a comprehensive visibility
  //            enumaration that captures the various behaviours.
  bool is_external{false};
  bool is_exported{false};
  bool is_thread_local{false};

  void ForwardTo(NativeObject *dest) const;

  virtual llvm::Constant *Pointer(void) const;
  virtual llvm::Constant *Address(void) const;

 protected:
  const NativeObject *Get(void) const;
  NativeObject *Get(void);
};

// Global variable defined inside of the lifted binary.
struct NativeVariable : public NativeObject {
 public:
  using NativeObject::NativeObject;

  virtual ~NativeVariable(void) = default;

  const NativeSegment *segment{nullptr};

  llvm::Constant *Pointer(void) const override;
  llvm::Constant *Address(void) const override;

  inline const NativeVariable *Get(void) const {
    return reinterpret_cast<const NativeVariable *>(this->NativeObject::Get());
  }

  NativeVariable *Get(void) {
    return reinterpret_cast<NativeVariable *>(this->NativeObject::Get());
  }
};

// Function that is defined inside the binary.
struct NativeFunction : public NativeObject {
 public:
  using NativeObject::NativeObject;

  virtual ~NativeFunction(void) = default;

  inline const NativeFunction *Get(void) const {
    return reinterpret_cast<const NativeFunction *>(this->NativeObject::Get());
  }

  NativeFunction *Get(void) {
    return reinterpret_cast<NativeFunction *>(this->NativeObject::Get());
  }

  llvm::SmallVector<std::unique_ptr<NativeExceptionFrame>, 2> eh_frame;

  // Defined in `Callback.cpp`.
  llvm::Constant *Pointer(void) const override;
  llvm::Constant *Address(void) const override;

  bool IsNoReturn(void) const;

  mutable const anvill::FunctionDecl *decl{nullptr};
  mutable llvm::Function *function{nullptr};
  mutable llvm::Function *lifted_function{nullptr};
  mutable llvm::Function *callable_lifted_function{nullptr};

  std::vector<const NativeBlock *> blocks;
};

struct NativeExceptionFrame : public NativeObject {
 public:
  using NativeObject::NativeObject;
  virtual ~NativeExceptionFrame(void) = default;

  uint64_t start_ea{0};
  uint64_t end_ea{0};
  uint64_t lp_ea{0};
  uint64_t action_index{0};
  mutable llvm::Value *lp_var{nullptr};
  std::unordered_map<uint64_t, NativeExternalVariable *> type_var;
};

// Function that is defined outside of the binary.
struct NativeExternalFunction : public NativeFunction {
 public:
  explicit NativeExternalFunction(NativeModule *module_);
  virtual ~NativeExternalFunction(void) = default;

  inline const NativeExternalFunction *Get(void) const {
    return reinterpret_cast<const NativeExternalFunction *>(
        this->NativeObject::Get());
  }

  NativeExternalFunction *Get(void) {
    return reinterpret_cast<NativeExternalFunction *>(
        this->NativeObject::Get());
  }

  // Defined in `External.cpp`.
  llvm::Constant *Pointer(void) const override;

  bool is_weak{false};
  unsigned num_args{0};

  llvm::CallingConv::ID cc;
};

// Global variable defined outside of the lifted binary.
struct NativeExternalVariable : public NativeVariable {
 public:
  using NativeVariable::NativeVariable;

  virtual ~NativeExternalVariable(void) = default;

  inline const NativeExternalVariable *Get(void) const {
    return reinterpret_cast<const NativeExternalVariable *>(
        this->NativeObject::Get());
  }

  NativeExternalVariable *Get(void) {
    return reinterpret_cast<NativeExternalVariable *>(
        this->NativeObject::Get());
  }

  // Defined in `External.cpp`.
  llvm::Constant *Pointer(void) const override;
  llvm::Constant *Address(void) const override;

  uint64_t size{0};
  bool is_weak{false};
};

// A cross-reference (xref) from data to something.
struct NativeXref {
  enum FixupKind : uint32_t { kAbsoluteFixup, kThreadLocalOffsetFixup };

  // Width (in bytes) of this cross-reference. This only makes sense for xrefs
  // embedded in the data section.
  uint32_t width{0};

  // Fixup type of this data-to-something xref.
  FixupKind fixup_kind{kAbsoluteFixup};

  // Location of the xref within its segment.
  uint64_t ea{0};

  // Target ea of the xref.
  uint64_t target_ea{0};

  // Bitmask to apply to this xref. Zero if none.
  uint64_t mask{0};

  // Segment containing `ea`.
  mutable const NativeSegment *segment{nullptr};

  // Segment containin `target_ea`.
  mutable const NativeSegment *target_segment{nullptr};

  // Global variable associated with `target_ea`.
  const NativeVariable *var{nullptr};

  // Function associated with `target_ea`.
  const NativeFunction *func{nullptr};
};

struct NativeBlob {
  uint64_t ea{0};
  unsigned size{0};
  bool is_zero{false};
};

struct NativeSegment : public NativeObject {
 public:
  using NativeObject::NativeObject;

  virtual ~NativeSegment(void) = default;

  inline const NativeSegment *Get(void) const {
    return reinterpret_cast<const NativeSegment *>(this->NativeObject::Get());
  }

  NativeSegment *Get(void) {
    return reinterpret_cast<NativeSegment *>(this->NativeObject::Get());
  }

  struct Entry {
    Entry(void) = default;
    Entry(uint64_t, uint64_t, NativeXref *, NativeBlob *);

    uint64_t ea = 0;
    uint64_t next_ea = 0;
    std::unique_ptr<NativeXref> xref;
    std::unique_ptr<NativeBlob> blob;
  };

  // Size, in bytes, of this segment.
  uint64_t size{0};

  // Whether or not this segment is read-only.
  bool is_read_only{false};

  // The external variable associated with this segment, if any.
  mutable NativeExternalVariable *as_extern_var{nullptr};

  // Partition of entries, which are either cross-references, or opaque
  // blobs of bytes. The ordering of entries is significant.
  std::map<uint64_t, Entry> entries;

  // Get or lazily create a global variable for this segment.
  //
  // NOTE(pag): Defined in Segment.cpp.
  llvm::Constant *Pointer(void) const override;
  llvm::Constant *Address(void) const override;
};

struct NativeModule : anvill::Program {

  std::unordered_set<uint64_t> exported_vars;

  // NOTE(pag): Using an `std::map` (as opposed to an `std::unordered_map`) is
  //            intentional so that we can get the ordering of `NativeSegment`s
  //            by their `ea`s.
  std::map<uint64_t, const NativeSegment *> ea_to_seg;

  std::vector<std::unique_ptr<NativeVariable>> variables;
  std::vector<std::unique_ptr<NativeFunction>> functions;

  // The lifted segments, including those invented for external variables.
  //
  // NOTE(pag): These are sorted by segment size (smallest first).
  std::vector<std::unique_ptr<NativeSegment>> segments;
  std::vector<std::unique_ptr<NativeSegment>> unused_segments;

  // All known basic blocks.
  std::unordered_map<uint64_t, std::unique_ptr<NativeBlock>> ea_to_block;

  // All known instructions and their cross-references.
  std::unordered_map<uint64_t, std::unique_ptr<NativeInstruction>> ea_to_inst;

  // All local and global functions.
  std::unordered_map<uint64_t, const NativeFunction *> ea_to_func;

  // Represent global and external variables.
  std::unordered_map<uint64_t, const NativeVariable *> ea_to_var;

  const NativeSegment *TryGetSegment(llvm::StringRef name) const;
  const NativeSegment *TryGetSegment(uint64_t ea) const;
  const NativeFunction *TryGetFunction(uint64_t ea) const;
  const NativeVariable *TryGetVariable(uint64_t ea) const;

  // Try to get the block containing `inst_ea`.
  const NativeBlock *TryGetBlock(uint64_t inst_ea,
                                 const NativeBlock *curr) const;

  // Try to get the instruction at `ea`.
  const NativeInstruction *TryGetInstruction(uint64_t ea) const;

  NativeSegment *TryGetSegment(uint64_t ea);
  NativeFunction *TryGetFunction(uint64_t ea);
  NativeVariable *TryGetVariable(uint64_t ea);

  // Sets of registers that may be preserved.
  std::vector<NativePreservedRegisters> preserved_regs;

  // Backup vector of instruction bytes.
  std::vector<std::unique_ptr<std::string>> inst_bytes;

  // Maps effective addresses to sets of registers that are preserved around
  // the instruction at this address. This corresponds to registers preserved
  // around a function call.
  std::unordered_map<uint64_t, const NativePreservedRegisters *>
      ea_to_inst_preserved_regs;

  // Maps effective addresses to sets of registers that are killed just after
  // the instruction at this address.
  std::unordered_map<uint64_t, const NativePreservedRegisters *>
      ea_to_inst_killed_regs;

  // Maps effective addresses to sets of registers that are preserved around
  // the instruction at this address. This corresponds to registers preserved
  // around a function call.
  std::unordered_multimap<uint64_t,
                          std::pair<uint64_t, const NativePreservedRegisters *>>
      ea_to_range_preserved_regs;

  template <typename T>
  void ForEachInstructionPreservedRegister(uint64_t ea, T cb) const {
    auto reg_set_it = ea_to_inst_preserved_regs.find(ea);
    if (reg_set_it != ea_to_inst_preserved_regs.end()) {
      for (const auto &reg_name : reg_set_it->second->reg_names) {
        cb(reg_name);
      }
    }
  }

  template <typename T>
  void ForEachInstructionKilledRegister(uint64_t ea, T cb) const {
    auto reg_set_it = ea_to_inst_killed_regs.find(ea);
    if (reg_set_it != ea_to_inst_killed_regs.end()) {
      for (const auto &reg_name : reg_set_it->second->reg_names) {
        cb(reg_name);
      }
    }
  }

  template <typename T>
  void ForEachRangePreservedRegister(uint64_t ea, T cb) const {
    for (auto reg_set_it = ea_to_range_preserved_regs.find(ea);
         (reg_set_it != ea_to_range_preserved_regs.end() &&
          reg_set_it->first == ea);
         ++reg_set_it) {
      cb(reg_set_it->second.first, *(reg_set_it->second.second));
    }
  }
};

NativeModule *ReadProtoBuf(const std::string &file_name, uint64_t pointer_size);

}  // namespace mcsema
