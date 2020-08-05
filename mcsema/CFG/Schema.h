/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

namespace mcsema::ws {

class Context;

struct Schema {

  static void CreateEnums(Context &ctx);

  static void CreateNMTables(Context &ctx);

  static void CreateSchema(Context &ctx);

  static void CreateTriggers(Context &ctx);
};

namespace schema {

template <typename C, typename T1, typename T2>
struct Other {
  using type = std::conditional_t<std::is_same_v<C, T1>, T2, T1>;
};

// Many of the simple tables that implement the storage follow the same structure,
// therefore a lot of queries can be automatically generated.
// Metaclasses below define minimum information that is required to do so.
// TODO(lukas): Since they are quite simple it would be perfect is queries that create
//              them would be derived automatically as well, but it sounds like non-trivial
//              work.

template <typename T1, typename T2>
struct NMTable {

  template <typename C>
  using other = typename Other<C, T1, T2>::type;

  template <typename C>
  using self = C;

  using fst = T1;
  using snd = T2;
};

using Query = const char *;

// `fk` represent the name this table uses for itself in other tables (e.g. n:m tables)
#define DEFINE_TABLE(name_, table_name_, foreign_key) \
  struct name_ { \
    constexpr static Query table_name = table_name_; \
    constexpr static Query fk = foreign_key; \
    constexpr static Query pk = "rowid"; \
    constexpr static Query is_populated = "SELECT COUNT(*) FROM " table_name_; \
    using table = name_; \
  }


DEFINE_TABLE(SymbolTableEntry, "symtabs", "symtab_rowid");
DEFINE_TABLE(MemoryRange, "memory_ranges", "memory_rowid");
DEFINE_TABLE(Module, "modules", "module_rowid");
DEFINE_TABLE(Function, "functions", "function_rowid");
DEFINE_TABLE(BasicBlock, "blocks", "bb_rowid");
DEFINE_TABLE(ExceptionFrame, "exception_frames", "frame_rowid");
DEFINE_TABLE(CodeXref, "code_references", "code_xref_rowid");
DEFINE_TABLE(DataXref, "data_references", "data_xref_rowid");
DEFINE_TABLE(ExternalFunction, "external_functions", "ext_function_rowid");
DEFINE_TABLE(GlobalVar, "global_variables", "g_var_rowid");
DEFINE_TABLE(ExternalVar, "external_variables", "ext_var_rowid");
DEFINE_TABLE(Segment, "segments", "segment_rowid");
DEFINE_TABLE(CallingConv, "calling_conventions", "calling_convention_rowid");
DEFINE_TABLE(OperandType, "operand_types", "operand_type_rowid");
DEFINE_TABLE(SymbolTableEntryType, "symtab_types", "type_rowid");
DEFINE_TABLE(FixupKind, "fixup_kinds", "fixup_kind_rowid");
DEFINE_TABLE(ExceptionFrameAction, "exception_frame_actions", "action");
DEFINE_TABLE(MemoryLocation, "memory_locations", "memory_location_rowid");
DEFINE_TABLE(ValueDecl, "value_decls", "value_decl_rowid");
DEFINE_TABLE(FuncDecl, "func_decls", "func_decl_rowid");
DEFINE_TABLE(PreservedRegs, "preserved_regs", "preserved_regs_rowid");

#undef DEFINE_TABLE

struct FrameToFunc : NMTable<Function, ExceptionFrame> {
  static constexpr Query table_name = "frame_to_func";
  using table = FrameToFunc;
};

struct BbToFunc : NMTable<BasicBlock, Function> {
  static constexpr Query table_name = "function_to_block";
  using table = BbToFunc;
};

struct FuncDeclParams : NMTable<FuncDecl, ValueDecl> {
  static constexpr Query table_name = "func_decl_params";
  using table = FuncDeclParams;
};

struct FuncDeclRets : NMTable<FuncDecl, ValueDecl> {
  static constexpr Query table_name = "func_decl_rets";
  using table = FuncDeclRets;
};

struct FuncSpec : NMTable<Function, FuncDecl> {
  static constexpr Query table_name = "func_spec";
  using table = FuncSpec;
};

struct ExtFuncSpec : NMTable<ExternalFunction, FuncDecl> {
  static constexpr Query table_name = "ext_func_spec";
  using table = ExtFuncSpec;
};

}  // namespace schema
}  // namespace mcsema::ws
