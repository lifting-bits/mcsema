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
#include <mcsema/CFG/Schema.h>


namespace mcsema::cfg {

void Schema::CreateEnums(Context &ctx) {
  auto &db = ctx.db;

  static Query action_enum = R"(create table if not exists exception_frame_actions(
        key integer PRIMARY KEY NOT NULL,
        action text NOT NULL
        ))";
  db.template query<action_enum>();

  static Query populate_action_enum =
    R"(insert into exception_frame_actions values(?1, ?2))";
  db.template query<populate_action_enum>(0, "Cleanup");
  db.template query<populate_action_enum>(1, "Catch");

  // rowid corresponds to llvm value for given cc
  static Query cc = R"(create table if not exists calling_conventions(
        name text NOT NULL
        ))";
  db.template query<cc>();

  static Query populate_cc = R"(insert into calling_conventions(rowid, name) values(?1, ?2))";
  db.template query<populate_cc>(0, "C");
  db.template query<populate_cc>(64, "X86_StdCall");
  db.template query<populate_cc>(65, "X86_FastCall");
  db.template query<populate_cc>(78, "X86_64_SysV");
  db.template query<populate_cc>(79, "Win64");

  static Query operand_types = R"(create table if not exists operand_types(
      type text NOT NULL
      ))";
  db.template query<operand_types>();

  static Query populate_operad_types =
    R"(insert into operand_types(rowid, type) values(?1, ?2))";
  db.template query<populate_operad_types>(0, "Immediate operand");
  db.template query<populate_operad_types>(1, "Memory operand");
  db.template query<populate_operad_types>(2, "MemoryDisplacement operand");
  db.template query<populate_operad_types>(3, "ControlFlow operand");
  db.template query<populate_operad_types>(4, "OffsetTable operand");

  static Query symtab_types = R"(create table if not exists symtab_types(
      type text NOT NULL
      ))";
  db.template query<symtab_types>();

  static Query populate_symtab_types =
    R"(insert into symtab_types(type, rowid) values(?1, ?2))";
  db.template query<populate_symtab_types>("imported", 1);
  db.template query<populate_symtab_types>("exported", 2);
  db.template query<populate_symtab_types>("internal", 3);
  db.template query<populate_symtab_types>("artificial", 4);

  static Query fixup_kinds =
    R"(create table if not exists fixup_kinds(
      type text NOT NULL
      ))";
  db.template query<fixup_kinds>();

  static Query populate_fixup_kinds =
    R"(insert into fixup_kinds(rowid, type) values(?1,?2))";
  db.template query<populate_fixup_kinds>(0, "Absolute");
  db.template query<populate_fixup_kinds>(1, "OffsetFromThreadBase");
}

void Schema::CreateNMTables(Context &ctx) {
  auto db = ctx.db;

  static Query q_func_2_block =
    R"(create table if not exists function_to_block(
       function_rowid integer NOT NULL,
       bb_rowid integer NOT NULL,
       UNIQUE(function_rowid, bb_rowid),
       FOREIGN KEY(function_rowid) REFERENCES functions(rowid),
       FOREIGN KEY(bb_rowid) REFERENCES blocks(rowid)
      ))";
  db.template query< q_func_2_block >();
}

void Schema::CreateSchema(Context &ctx) {
  auto db = ctx.db;

  CreateEnums(ctx);

  static Query c_module =
    R"(create table if not exists modules(
       name text
      ))";
  db.template query<c_module>();

  static Query c_module_meta =
    R"(create table if not exists module_meta(
       name text,
       arch text,
       os text))";
  db.template query<c_module_meta>();

  static Query functions = R"(create table if not exists functions(
        ea integer NOT NULL,
        is_entrypoint integer,
        symtab_rowid integer DEFAULT NULL,
        module_rowid integer NOT NULL,
        FOREIGN KEY(module_rowid) REFERENCES modules(rowid),
        FOREIGN KEY(symtab_rowid) REFERENCES symtabs(rowid)
        ))";
  db.template query<functions>();

  static Query memory_ranges = R"(create table if not exists memory_ranges(
    ea integer NOT NULL,
    size integer,
    module_rowid integer,
    bytes blob,
    FOREIGN KEY(module_rowid) REFERENCES modules(rowid)
  ))";

  db.template query<memory_ranges>();

  static Query blocks = R"(create table if not exists blocks(
        ea integer NOT NULL,
        size integer,
        module_rowid integer,
        memory_rowid integer,
        FOREIGN KEY(module_rowid) REFERENCES modules(rowid),
        FOREIGN KEY(memory_rowid) REFERENCES memory_ranges(rowid)
        ))";
  db.template query<blocks>();

  static Query segments = R"(create table if not exists segments(
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
        name text NOT NULL,
        module_rowid integer NOT NULL,
        type_rowid integer NOT NULL,
        FOREIGN KEY(type_rowid) REFERENCES symtab_types(rowid),
        FOREIGN KEY(module_rowid) REFERENCES modules(rowid)
        ))";
  db.template query<symtabs>();

  // TODO: Signature
  static Query external_functions = R"(create table if not exists external_functions(
        ea integer NOT NULL,
        calling_convention_rowid integer NOT NULL,
        symtab_rowid integer NOT NULL,
        module_rowid integer NOT NULL,
        has_return integer,
        is_weak integer,
        signature text,
        FOREIGN KEY(calling_convention_rowid) REFERENCES calling_conventions(rowid),
        FOREIGN KEY(symtab_rowid) REFERENCES symtabs(rowid),
        FOREIGN KEY(module_rowid) REFERENCES modules(rowid)
        ))";
  db.template query<external_functions>();

  static Query code_xrefs = R"(create table if not exists code_references(
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
        ea integer,
        name text,
        size integer))";
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

  static Query exception_frames = R"(create table if not exists exception_frames(
        func_ea integer,
        start_ea integer,
        end_ea integer,
        lp_ea integer,
        action NOT NULL REFERENCES exception_frame_actions(key)
        ))";
  db.template query<exception_frames>();

  static Query external_vars = R"(create table if not exists external_variables(
        ea integer,
        name text,
        size integer,
        is_weak integer,
        is_thread_local integer
        ))";
  db.template query<external_vars>();

  CreateNMTables(ctx);
  CreateTriggers(ctx);
}

void Schema::CreateTriggers(Context &ctx) {
  static Query delete_block = R"(
    CREATE TRIGGER delete_bb_cascade
      AFTER DELETE ON blocks
      FOR EACH ROW
      BEGIN
          DELETE FROM code_references WHERE OLD.rowid = code_references.bb_rowid;
      END
  )";
  ctx.db.template query<delete_block>();

}

} // namespace mcsema::cfg
