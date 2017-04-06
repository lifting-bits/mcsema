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

#ifndef MCSEMA_CFG_CFG_H_
#define MCSEMA_CFG_CFG_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace mcsema {

struct NativeVariable;
struct NativeFunction;

struct NativeExternalVariable;
struct NativeExternalFunction;

struct NativeSegment;
struct NativeXref;

struct NativeInstruction {
 public:
  uint64_t ea;
  std::string bytes;

  const NativeXref *flow;
  const NativeXref *mem;
  const NativeXref *imm;
  const NativeXref *disp;

  bool does_not_return;
  uint64_t offset_table;
};

struct NativeBlock {
 public:
  uint64_t ea;
  std::string lifted_name;
  std::vector<const NativeInstruction *> instructions;
  std::unordered_set<uint64_t> successor_eas;
};

// Generic object used in the binary. This includes both internally and
// externally defined. In practice, those externally defined objects still
// have meaningful and unique effective addresses, usually pointing to
// some kind of relocation section within the binary.
struct NativeObject {
 public:
  uint64_t ea;
  std::string name;  // Name in the binary.
  std::string lifted_name;  // Name in the bitcode.
  bool is_external;
};

// Function that is defined inside the binary.
struct NativeFunction : public NativeObject {
 public:
  std::unordered_map<uint64_t, const NativeBlock *> blocks;
};

// Function that is defined outside of the binary.
struct NativeExternalFunction : public NativeFunction {
 public:

};

// Global variable defined inside of the lifted binary.
struct NativeVariable : public NativeObject {
 public:
  const NativeSegment *segment;
};

// Global variable defined outside of the lifted binary.
struct NativeExternalVariable : public NativeVariable {
 public:
  uint64_t size;
  bool is_weak;
};

// A cross-reference to something.
struct NativeXref {
 public:
  uint64_t width;  // In bytes.
  uint64_t ea;  // Location of the xref within its segment.
  const NativeSegment *segment;  // Segment containing the xref.

  uint64_t target_ea;
  std::string target_name;
  const NativeSegment *target_segment;  // Target segment of the xref, if any.

  const NativeVariable *var;
  const NativeFunction *func;
};

struct NativeBlob {
 public:
  uint64_t ea;
  std::string data;
};

struct NativeSegment : public NativeObject {
 public:
  struct Entry {
   public:
    uint64_t ea;
    uint64_t next_ea;
    const NativeXref *xref;
    const NativeBlob *blob;
  };

  uint64_t size;
  bool is_read_only;

  // Partition of entries, which are either cross-references, or opaque
  // blobs of bytes. The ordering of entries is significant.
  std::map<uint64_t, Entry> entries;
};

struct NativeModule {
 public:
  std::unordered_set<uint64_t> exported_vars;
  std::unordered_set<uint64_t> exported_funcs;

  // List of segments, keyed by the *ending* address of the segment, which
  // permits lower bound queries to work to find things inside of the segment.
  std::map<uint64_t, NativeSegment *> segments;

  std::unordered_map<uint64_t, const NativeFunction *> ea_to_func;

  std::unordered_map<std::string, const NativeExternalFunction *>
      name_to_extern_func;

  // Represent global and external variables.
  std::unordered_map<uint64_t, const NativeVariable *> ea_to_var;
  std::unordered_map<std::string, const NativeExternalVariable *>
      name_to_extern_var;

  std::unordered_map<uint64_t, const NativeXref *> code_xrefs;

  const NativeFunction *TryGetFunction(uint64_t ea) const;
  const NativeVariable *TryGetVariable(uint64_t ea) const;
};

NativeModule *ReadProtoBuf(const std::string &file_name);

}  // namespace mcsema

#endif  // MCSEMA_CFG_CFG_H_
