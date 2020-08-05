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


#include <mcsema/CFG/Context.h>
#include <mcsema/CFG/Enums.h>
#include <mcsema/CFG/Schema.h>

namespace mcsema::ws {

template <typename Table>
int64_t RowCount(Context &ctx) {
  return ctx.db.template query<Table::is_populated>()
      .template GetScalar_r<int64_t>();
}

template <typename E>
constexpr auto lower(E e) {
  return static_cast<std::underlying_type_t<E>>(e);
}

void Schema::CreateEnums(Context &ctx) {
  auto &db = ctx.db;

  static Query action_enum =
      R"(create table if not exists exception_frame_actions(
        rowid integer PRIMARY KEY NOT NULL,
        action text NOT NULL
        ))";
  db.template query<action_enum>();

  static Query populate_action_enum =
      R"(insert into exception_frame_actions(rowid, action) values(?1, ?2))";

  if (!RowCount<schema::ExceptionFrameAction>(ctx)) {
    db.template query<populate_action_enum>(lower(Action::Cleanup),
                                            to_string(Action::Cleanup));

    db.template query<populate_action_enum>(lower(Action::Catch),
                                            to_string(Action::Catch));
  }
  // rowid corresponds to llvm value for given cc
  static Query cc = R"(create table if not exists calling_conventions(
        rowid INTEGER PRIMARY KEY,
        name text NOT NULL
        ))";
  db.template query<cc>();

  static Query populate_cc =
      R"(insert into calling_conventions(rowid, name) values(?1, ?2))";
  if (!RowCount<schema::CallingConv>(ctx)) {
    for (auto cc : AllCCs()) {
      db.template query<populate_cc>(lower(cc), to_string(cc));
    }
  }

  static Query operand_types = R"(create table if not exists operand_types(
      rowid INTEGER PRIMARY KEY,
      type text NOT NULL
      ))";
  db.template query<operand_types>();

  static Query populate_operad_types =
      R"(insert into operand_types(rowid, type) values(?1, ?2))";

  if (!RowCount<schema::OperandType>(ctx)) {
    for (auto ot : AllOperandTypes()) {
      db.template query<populate_operad_types>(lower(ot), to_string(ot));
    }
  }

  static Query symtab_types = R"(create table if not exists symtab_types(
      rowid INTEGER PRIMARY KEY,
      type text NOT NULL
      ))";
  db.template query<symtab_types>();

  static Query populate_symtab_types =
      R"(insert into symtab_types(type, rowid) values(?2, ?1))";

  if (!RowCount<schema::SymbolTableEntryType>(ctx)) {
    for (auto sv_ : AllSymbolVisibilities()) {
      db.template query<populate_symtab_types>(lower(sv_), to_string(sv_));
    }
  }

  static Query fixup_kinds =
      R"(create table if not exists fixup_kinds(
      rowid INTEGER PRIMARY KEY,
      type text NOT NULL
      ))";
  db.template query<fixup_kinds>();

  static Query populate_fixup_kinds =
      R"(insert into fixup_kinds(rowid, type) values(?1,?2))";

  if (!RowCount<schema::FixupKind>(ctx)) {
    db.template query<populate_fixup_kinds>(lower(FixupKind::Absolute),
                                            to_string(FixupKind::Absolute));

    db.template query<populate_fixup_kinds>(
        lower(FixupKind::OffsetFromThreadBase),
        to_string(FixupKind::OffsetFromThreadBase));
  }
}

void Schema::CreateNMTables(Context &ctx) {
  auto &db = ctx.db;

  static Query q_func_2_block =
      R"(create table if not exists function_to_block(
       function_rowid integer NOT NULL,
       bb_rowid integer NOT NULL,
       UNIQUE(function_rowid, bb_rowid),
       FOREIGN KEY(function_rowid) REFERENCES functions(rowid) ON DELETE CASCADE,
       FOREIGN KEY(bb_rowid) REFERENCES blocks(rowid) ON DELETE CASCADE
      ))";
  db.template query<q_func_2_block>();

  static Query q_bb_successors =
      R"(CREATE TABLE IF NOT EXISTS bb_successors(
        from_rowid integer NOT NULL,
        to_rowid integer NOT NULL,
        UNIQUE(from_rowid, to_rowid),
        FOREIGN KEY(from_rowid) REFERENCES blocks(rowid) ON DELETE CASCADE,
        FOREIGN KEY(to_rowid) REFERENCES blocks(rowid) ON DELETE CASCADE
      ))";
  db.template query<q_bb_successors>();

  static Query q_exception_frame_2_type =
      R"(CREATE TABLE IF NOT EXISTS frame_to_type(
        frame_rowid integer NOT NULL,
        var_rowid integer NOT NULL,
        UNIQUE(frame_rowid, var_rowid),
        FOREIGN KEY(frame_rowid) REFERENCES exception_frames(rowid) ON DELETE CASCADE,
        FOREIGN KEY(var_rowid) REFERENCES external_variables(rowid) ON DELETE CASCADE
        ))";
  db.template query<q_exception_frame_2_type>();

  static Query q_exception_frame_2_func =
      R"(CREATE TABLE IF NOT EXISTS frame_to_func(
        frame_rowid integer NOT NULL,
        function_rowid integer NOT NULL,
        UNIQUE(frame_rowid, function_rowid),
        FOREIGN KEY(frame_rowid) REFERENCES exception_frames(rowid) ON DELETE CASCADE,
        FOREIGN KEY(function_rowid) REFERENCES functions(rowid) ON DELETE CASCADE
        ))";
  db.template query<q_exception_frame_2_func>();

  static Query q_func_decl_params =
      R"(CREATE TABLE IF NOT EXISTS func_decl_params(
        value_decl_rowid integer NOT NULL,
        func_decl_rowid integer NOT NULL,
        UNIQUE(value_decl_rowid, func_decl_rowid),
        FOREIGN KEY(value_decl_rowid) REFERENCES value_decls(rowid) ON DELETE CASCADE,
        FOREIGN KEY(func_decl_rowid) REFERENCES func_decls(rowid) ON DELETE CASCADE
        ))";
  db.template query<q_func_decl_params>();

  static Query q_func_decl_rets = R"(CREATE TABLE IF NOT EXISTS func_decl_rets(
        value_decl_rowid integer NOT NULL,
        func_decl_rowid integer NOT NULL,
        UNIQUE(value_decl_rowid, func_decl_rowid),
        FOREIGN KEY(value_decl_rowid) REFERENCES value_decls(rowid) ON DELETE CASCADE,
        FOREIGN KEY(func_decl_rowid) REFERENCES func_decls(rowid) ON DELETE CASCADE
        ))";
  db.template query<q_func_decl_rets>();

  static Query q_func_spec = R"(CREATE TABLE IF NOT EXISTS func_spec(
        function_rowid integer NOT NULL,
        func_decl_rowid integer NOT NULL,
        UNIQUE(function_rowid, func_decl_rowid),
        FOREIGN KEY(function_rowid) REFERENCES functions(rowid) ON DELETE CASCADE,
        FOREIGN KEY(func_decl_rowid) REFERENCES func_decls(rowid) ON DELETE CASCADE
        ))";
  db.template query<q_func_spec>();

  static Query q_ext_func_spec = R"(CREATE TABLE IF NOT EXISTS ext_func_spec(
        ext_function_rowid integer NOT NULL,
        func_decl_rowid integer NOT NULL,
        UNIQUE(ext_function_rowid, func_decl_rowid),
        FOREIGN KEY(ext_function_rowid) REFERENCES external_functions(rowid) ON DELETE CASCADE,
        FOREIGN KEY(func_decl_rowid) REFERENCES func_decls(rowid) ON DELETE CASCADE
        ))";
  db.template query<q_ext_func_spec>();

  static Query q_preservation_range =
      R"(CREATE TABLE IF NOT EXISTS preservation_range(
        preserved_regs_rowid integer NOT NULL,
        begin integer NOT NULL,
        end integer,
        FOREIGN KEY(preserved_regs_rowid) REFERENCES preserved_regs(rowid)
        ))";
  db.template query<q_preservation_range>();

  static Query q_preserved_regs_regs =
      R"(CREATE TABLE IF NOT EXISTS preserved_regs_regs(
        preserved_regs_rowid integer NOT NULL,
        reg text NOT NULL,
        FOREIGN KEY(preserved_regs_rowid) REFERENCES preserved_regs(rowid)
        ))";
  db.template query<q_preserved_regs_regs>();
}

void Schema::CreateSchema(Context &ctx) {
  auto &db = ctx.db;

  CreateEnums(ctx);

  static Query c_module =
      R"(create table if not exists modules(
       name text UNIQUE,
       rowid INTEGER PRIMARY KEY
      ))";
  db.template query<c_module>();

  static Query c_module_meta =
      R"(create table if not exists module_meta(
       name text,
       arch text,
       os text))";
  db.template query<c_module_meta>();

  static Query functions = R"(create table if not exists functions(
        rowid INTEGER PRIMARY KEY,
        ea integer NOT NULL,
        is_entrypoint integer,
        symtab_rowid integer DEFAULT NULL,
        module_rowid integer NOT NULL,
        FOREIGN KEY(module_rowid) REFERENCES modules(rowid),
        FOREIGN KEY(symtab_rowid) REFERENCES symtabs(rowid)
        ))";
  db.template query<functions>();

  static Query memory_ranges = R"(create table if not exists memory_ranges(
    rowid INTEGER PRIMARY KEY,
    ea integer NOT NULL,
    size integer,
    module_rowid integer,
    bytes blob,
    FOREIGN KEY(module_rowid) REFERENCES modules(rowid)
  ))";

  db.template query<memory_ranges>();

  static Query blocks = R"(create table if not exists blocks(
        rowid INTEGER PRIMARY KEY,
        ea integer NOT NULL,
        size integer,
        module_rowid integer,
        memory_rowid integer,
        FOREIGN KEY(module_rowid) REFERENCES modules(rowid),
        FOREIGN KEY(memory_rowid) REFERENCES memory_ranges(rowid)
        ))";
  db.template query<blocks>();

  static Query segments = R"(create table if not exists segments(
        rowid INTEGER PRIMARY KEY,
        ea integer NOT NULL,
        size integer,
        read_only integer,
        is_external integer,
        is_exported integer,
        is_thread_local integer,
        variable_name text,
        memory_rowid integer,
        FOREIGN KEY(memory_rowid) REFERENCES memory_ranges(rowid)
        ))";
  db.template query<segments>();

  static Query symtabs = R"(create table if not exists symtabs(
        rowid INTEGER PRIMARY KEY,
        name text NOT NULL,
        module_rowid integer NOT NULL,
        type_rowid integer NOT NULL,
        FOREIGN KEY(type_rowid) REFERENCES symtab_types(rowid),
        FOREIGN KEY(module_rowid) REFERENCES modules(rowid)
        ))";
  db.template query<symtabs>();

  // TODO: Signature
  static Query external_functions =
      R"(create table if not exists external_functions(
        rowid INTEGER PRIMARY KEY,
        ea integer NOT NULL,
        calling_convention_rowid integer NOT NULL,
        symtab_rowid integer NOT NULL,
        module_rowid integer NOT NULL,
        has_return integer,
        is_weak integer,
        FOREIGN KEY(calling_convention_rowid) REFERENCES calling_conventions(rowid),
        FOREIGN KEY(symtab_rowid) REFERENCES symtabs(rowid),
        FOREIGN KEY(module_rowid) REFERENCES modules(rowid)
        ))";
  db.template query<external_functions>();

  static Query code_xrefs = R"(create table if not exists code_references(
        rowid INTEGER PRIMARY KEY,
        ea integer NOT NULL,
        target_ea integer NOT NULL,
        bb_rowid NOT NULL,
        operand_type_rowid NOT NULL,
        mask integer,
        symtab_rowid,
        FOREIGN KEY(bb_rowid) REFERENCES blocks(rowid),
        FOREIGN KEY(operand_type_rowid) REFERENCES operand_types(rowid),
        FOREIGN KEY(symtab_rowid) REFERENCES symtabs(rowid)
        ))";
  db.template query<code_xrefs>();


  static Query data_xrefs = R"(create table if not exists data_references(
        rowid INTEGER PRIMARY KEY,
        ea integer NOT NULL,
        width integer NOT NULL,
        target_ea integer NOT NULL,
        segment_rowid integer NOT NULL,
        fixup_kind_rowid integer NOT NULL,
        symtab_rowid integer,
        FOREIGN KEY(segment_rowid) REFERENCES segments(rowid),
        FOREIGN KEY(fixup_kind_rowid) REFERENCES fixup_kinds(rowid),
        FOREIGN KEY(symtab_rowid) REFERENCES symtabs(rowid)
        ))";
  db.template query<data_xrefs>();

  // TODO: Rework/Check below

  static Query g_vars = R"(create table if not exists global_variables(
        rowid INTEGER PRIMARY KEY,
        ea integer,
        name text,
        size integer,
        module_rowid integer NOT NULL,
        FOREIGN KEY(module_rowid) REFERENCES modules(rowid)))";
  db.template query<g_vars>();

  static Query vars = R"(create table if not exists variables(
        ea integer,
        name text))";
  db.template query<vars>();

  static Query stack_vars = R"(create table if not exists stack_variables(
        name text,
        size integer,
        sp_offset integer,
        has_frame integer,
        reg_name text
        ))";
  db.template query<stack_vars>();

  static Query exception_frames =
      R"(create table if not exists exception_frames(
        rowid INTEGER PRIMARY KEY,
        start_ea integer,
        end_ea integer,
        lp_ea integer,
        action_rowid integer NOT NULL,
        FOREIGN KEY(action_rowid) REFERENCES exception_frame_actions(rowid)
        ))";
  db.template query<exception_frames>();

  static Query external_vars = R"(create table if not exists external_variables(
        rowid INTEGER PRIMARY KEY,
        ea integer NOT NULL,
        name text,
        size integer,
        is_weak integer,
        is_thread_local integer,
        module_rowid integer NOT NULL,
        FOREIGN KEY(module_rowid) REFERENCES modules(rowid)))";
  db.template query<external_vars>();

  static Query memory_locations =
      R"(create table if not exists memory_locations(
        rowid INTEGER PRIMARY KEY,
        register text NOT NULL,
        offset integer,
        UNIQUE(register, offset)))";
  db.template query<memory_locations>();

  // TODO: Index
  static Query value_decls = R"(create table if not exists value_decls(
        rowid INTEGER PRIMARY KEY,
        type text NOT NULL,
        register text,
        name text,
        memory_location_rowid integer,
        FOREIGN KEY(memory_location_rowid) REFERENCES memory_locations (rowid),
        UNIQUE(type, register, name, memory_location_rowid)
        ))";
  db.template query<value_decls>();

  static Query func_decls = R"(create table if not exists func_decls(
        rowid INTEGER PRIMARY KEY,
        ret_address_rowid integer NOT NULL,
        ret_stack_ptr_rowid integer NOT NULL,
        is_variadic integer NOT NULL,
        is_noreturn integer NOT NULL,
        calling_convention_rowid integer,
        FOREIGN KEY(ret_address_rowid) REFERENCES value_decls(rowid)
        FOREIGN KEY(ret_stack_ptr_rowid) REFERENCES value_decls(rowid)
        FOREIGN KEY(calling_convention_rowid) REFERENCES calling_conventions(rowid)
        ))";
  db.template query<func_decls>();

  static Query preserved_regs = R"(create table if not exists preserved_regs(
        rowid INTEGER PRIMARY KEY,
        module_rowid integer NOT NULL,
        is_alive integer NOT NULL,
        FOREIGN KEY(module_rowid) REFERENCES modules(rowid)
        ))";
  db.template query<preserved_regs>();

  CreateNMTables(ctx);
  CreateTriggers(ctx);
}

void Schema::CreateTriggers(Context &ctx) {
  static Query delete_block = R"(
    CREATE TRIGGER IF NOT EXISTS delete_bb_cascade
      AFTER DELETE ON blocks
      FOR EACH ROW
      BEGIN
          DELETE FROM code_references WHERE OLD.rowid = code_references.bb_rowid;
      END
  )";
  ctx.db.template query<delete_block>();
}

}  // namespace mcsema::ws
