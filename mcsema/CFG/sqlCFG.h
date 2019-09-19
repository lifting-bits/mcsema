#pragma once

#include "mcsema/CFG/SQLiteWrapper.h"

namespace mcsema {
namespace sqlcfg {

template< const auto &name >
struct Module {
  using db = sqlite::Database< name >;
  using Query = const char *;

  static void CreateEnums() {

    static Query action_enum = R"(create table if not exists exception_frame_actions(
          key integer PRIMARY KEY NOT NULL,
          action text NOT NULL
          ))";
    db::template query<action_enum>();

    static Query populate_action_enum =
      R"(insert into exception_frame_actions values(?1, ?2))";
    db::template query<populate_action_enum>(0, "Cleanup");
    db::template query<populate_action_enum>(1, "Catch");

    static Query cc = R"(create table if not exists calling_conventions(
          key integer PRIMARY KEY NOT NULL,
          calling_convention text NOT NULL
          ))";
    db::template query<cc>();

    static Query populate_cc = R"(insert into calling_conventions values(?1, ?2))";
    db::template query<populate_cc>(0, "CallerCleanup");
    db::template query<populate_cc>(1, "CalleeCleanup");
    db::template query<populate_cc>(2, "FastCall");

    static Query operand_types = R"(create table if not exists operand_types(
        key PRIMARY KEY NOT NULL,
        type text
        ))";
    db::template query<operand_types>();

    static Query populate_operad_types = R"(insert into operand_types values(?1, ?2))";
    db::template query<populate_operad_types>(0, "Immediate operand");
    db::template query<populate_operad_types>(1, "Memory operand");
    db::template query<populate_operad_types>(2, "MemoryDisplacement operand");
    db::template query<populate_operad_types>(3, "ControlFlow operand");
    db::template query<populate_operad_types>(4, "OffsetTable operand");


    static Query locations = R"(create table if not exists locations(
          key integer PRIMARY KEY NOT NULL,
          location text NOT NULL
          ))";
    db::template query<locations>();

    static Query populate_locations = R"(insert into locations values(?1, ?2))";
    db::template query<populate_locations>(0, "Internal");
    db::template query<populate_locations>(1, "External");

  }

  static void CreateScheme() {
    CreateEnums();

    static Query c_module_meta =
      R"(create table if not exists module_meta(
         name text,
         arch text,
         os text))";
    db::template query<c_module_meta>();

    static Query g_vars = R"(create table if not exists global_variables(
          ea integer,
          name text,
          size integer))";
    db::template query<g_vars>();

    static Query vars = R"(create table if not exists variables(
          ea integer,
          name text))";
    db::template query<vars>();

    static Query segments = R"(create table if not exists segments(
          ea integer,
          data blob,
          read_only integer,
          is_external integer,
          is_exported integer,
          is_thread_local integer,
          variable_name text
          ))";
    db::template query<segments>();

    static Query stack_vars = R"(create table if not exists stack_variables(
          name text,
          size integer,
          sp_offset integer,
          has_frame integer,
          reg_name text
          ))";
    db::template query<stack_vars>();

    static Query exception_frames = R"(create table if not exists exception_frames(
          func_ea integer,
          start_ea integer,
          end_ea integer,
          lp_ea integer,
          action NOT NULL REFERENCES exception_frame_actions(key)
          ))";
    db::template query<exception_frames>();

    static Query external_vars = R"(create table if not exists external_variables(
          ea integer,
          name text,
          size integer,
          is_weak integer,
          is_thread_local integer
          ))";
    db::template query<external_vars>();

    static Query external_functions = R"(create table if not exists external_functions(
          ea integer,
          name text,
          cc NOT NULL REFERENCES calling_conventions(key),
          has_return integer,
          is_weak integer,
          signature text
          ))";
    db::template query<external_functions>();

    static Query functions = R"(create table if not exists functions(
          ea integer,
          is_entrypoint integer,
          name text
          ))";
    db::template query<functions>();

    static Query blocks = R"(create table if not exists blocks(
          ea integer,
          bytes blob
          ))";
    db::template query<blocks>();

    static Query code_xrefs = R"(create table if not exists code_references(
          ea integer,
          target_type NOT NULL REFERENCES operand_types(key),
          location NOT NULL REFERENCES locations(key),
          mask integer,
          name text
          ))";
    db::template query<code_xrefs>();
  }
};


} // namespace sqlcfg
} // namespace mcsema
