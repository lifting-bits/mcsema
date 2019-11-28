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


#include <mcsema/CFG/Schema.h>

namespace mcsema::cfg {

void Schema::CreateEnums(Database db) {

  static Query action_enum = R"(create table if not exists exception_frame_actions(
        key integer PRIMARY KEY NOT NULL,
        action text NOT NULL
        ))";
  db.template query<action_enum>();

  static Query populate_action_enum =
    R"(insert into exception_frame_actions values(?1, ?2))";
  db.template query<populate_action_enum>(0, "Cleanup");
  db.template query<populate_action_enum>(1, "Catch");

  static Query cc = R"(create table if not exists calling_conventions(
        key integer PRIMARY KEY NOT NULL,
        calling_convention text NOT NULL
        ))";
  db.template query<cc>();

  static Query populate_cc = R"(insert into calling_conventions values(?1, ?2))";
  db.template query<populate_cc>(0, "CallerCleanup");
  db.template query<populate_cc>(1, "CalleeCleanup");
  db.template query<populate_cc>(2, "FastCall");

  static Query operand_types = R"(create table if not exists operand_types(
      key PRIMARY KEY NOT NULL,
      type text
      ))";
  db.template query<operand_types>();

  static Query populate_operad_types = R"(insert into operand_types values(?1, ?2))";
  db.template query<populate_operad_types>(0, "Immediate operand");
  db.template query<populate_operad_types>(1, "Memory operand");
  db.template query<populate_operad_types>(2, "MemoryDisplacement operand");
  db.template query<populate_operad_types>(3, "ControlFlow operand");
  db.template query<populate_operad_types>(4, "OffsetTable operand");


  static Query locations = R"(create table if not exists locations(
        key integer PRIMARY KEY NOT NULL,
        location text NOT NULL
        ))";
  db.template query<locations>();

  static Query populate_locations = R"(insert into locations values(?1, ?2))";
  db.template query<populate_locations>(0, "Internal");
  db.template query<populate_locations>(1, "External");


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
}

void Schema::CreateNMTables(Database db)
{
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

void Schema::CreateSchema(Database db) {
  CreateEnums(db);

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
        name text,
        module_rowid integer,
        FOREIGN KEY(module_rowid) REFERENCES modules(rowid)
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

  static Query external_functions = R"(create table if not exists external_functions(
        ea integer,
        name text,
        cc NOT NULL REFERENCES calling_conventions(key),
        has_return integer,
        is_weak integer,
        signature text
        ))";
  db.template query<external_functions>();

  static Query code_xrefs = R"(create table if not exists code_references(
        ea integer,
        target_type NOT NULL REFERENCES operand_types(key),
        location NOT NULL REFERENCES locations(key),
        mask integer,
        name text
        ))";
  db.template query<code_xrefs>();

  CreateNMTables(db);
}

} // namespace mcsema::cfg
