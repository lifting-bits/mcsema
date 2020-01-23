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

namespace mcsema::cfg {

/* Enums */
enum class SymtabEntryType : unsigned char {
  Imported = 1, // Names from another object file
  Exported = 2, // Externally visible
  Internal = 3, // Internal

  // If there is an object in the binary that can have a name but does not someone may
  // want to give it a name, but since it originally was not in the binary neither
  // option above fits, therefore Artificial should be used.
  // It is neither imported, exported or internal,
  // since it was not present in the original binary.
  Artificial = 4
};


// Corresponds to llvm calling convention numbering
// NOTE(lukas): llvm header is not included since dependency on llvm is not worth
enum class CallingConv : unsigned char {
  C = 0,
  X86_StdCall = 64,
  X86_FastCall = 65,
  X86_64_SysV = 78,
  Win64 = 79
};

enum class OperandType : unsigned char {
  Immediate = 0,
  Memory = 1,
  MemoryDisplacement = 2,
  ControlFlow = 3,
  OffsetTable = 4
};

enum class FixupKind : unsigned char {
  Absolute = 0,
  OffsetFromThreadBase = 1
};

}// namespace mcsema::cfg
