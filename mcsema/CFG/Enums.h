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

#include <string_view>

namespace mcsema::ws {

/* Enums */
enum class SymbolVisibility: unsigned char {
  Imported = 1,  // Names from another object file
  Exported = 2,  // Externally visible
  Internal = 3,  // Internal

  // If there is an object in the binary that can have a name but does not someone may
  // want to give it a name, but since it originally was not in the binary neither
  // option above fits, therefore Artificial should be used.
  // It is neither imported, exported or internal,
  // since it was not present in the original binary.
  Artificial = 4
};

static inline constexpr std::string_view to_string(SymbolVisibility sv) {
  using namespace std::literals;
  switch(sv) {
    case SymbolVisibility::Imported  : return "Imported"sv;
    case SymbolVisibility::Exported  : return "Exported"sv;
    case SymbolVisibility::Internal  : return "Internal"sv;
    case SymbolVisibility::Artificial: return "Artificial"sv;

  }
}

// Corresponds to llvm calling convention numbering
// NOTE(lukas): llvm header is not included since dependency on llvm is not worth
enum class CallingConv : unsigned char {
  C = 0,
  X86_StdCall = 64,
  X86_FastCall = 65,
  X86_ThisCall = 70,
  X86_64_SysV = 78,
  Win64 = 79,
  X86_VectorCall = 80,
  X86_RegCall = 92,
  AArch64_VectorCall = 97
};

static inline constexpr std::string_view to_string(CallingConv c) {
  using namespace std::literals;
  switch (c) {
    case CallingConv::C                  : return "C"sv;
    case CallingConv::X86_StdCall        : return "X86_StdCall"sv;
    case CallingConv::X86_FastCall       : return "X86_FastCall"sv;
    case CallingConv::X86_ThisCall       : return "X86_ThisCall"sv;
    case CallingConv::X86_64_SysV        : return "X86_64_SysV"sv;
    case CallingConv::Win64              : return "Win64"sv;
    case CallingConv::X86_VectorCall     : return "X86_VectorCall"sv;
    case CallingConv::X86_RegCall        : return "X86_RegCall"sv;
    case CallingConv::AArch64_VectorCall : return "AArch64_VectorCall"sv;
  }
}

enum class OperandType : unsigned char {
  Immediate = 0,
  Memory = 1,
  MemoryDisplacement = 2,
  ControlFlow = 3,
  OffsetTable = 4
};

static inline constexpr std::string_view to_string(OperandType ot) {
  using namespace std::literals;
  switch(ot) {
    case OperandType::Immediate          : return "Immediate"sv;
    case OperandType::Memory             : return "Memory"sv;
    case OperandType::MemoryDisplacement : return "MemoryDisplacement"sv;
    case OperandType::ControlFlow        : return "ControlFlow"sv;
    case OperandType::OffsetTable        : return "OffsetTable"sv;
  }
}

enum class FixupKind : unsigned char {
  Absolute = 0,
  OffsetFromThreadBase = 1
};

static inline constexpr std::string_view to_string(FixupKind fk) {
  using namespace std::literals;
  switch(fk) {
    case FixupKind::Absolute             : return "Absolute"sv;
    case FixupKind::OffsetFromThreadBase : return "OffsetFromThreadBase"sv;
  }
}

enum class Action : unsigned char {
  Cleanup = 0,
  Catch = 1
};

static inline constexpr std::string_view to_string(Action a) {
  using namespace std::literals;
  switch(a) {
    case Action::Cleanup : return "Cleanup"sv;
    case Action::Catch   : return "Catch"sv;
  }
}

}// namespace mcsema::ws
