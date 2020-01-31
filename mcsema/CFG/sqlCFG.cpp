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

#include <memory>
#include <utility>
#include <type_traits>

#include <mcsema/CFG/Types.h>
#include <mcsema/CFG/Util.h>

#include <mcsema/CFG/sqlCFG.h>
#include <mcsema/CFG/Schema.h>
#include <mcsema/CFG/Context.h>

namespace mcsema {
namespace cfg {

/* This file contains mapping from public API -> internal implementations and definitions
 * of these implementations.
 * If public API has object X there should be object X_ that implements it
 * (something like pimpl idiom).
 * These object are templated by their Concrete (public API) objects, which was used
 * in older version but currently is not and will probably be removed.
 * Design tries to hide all wrapper code away in CRTP classes (see `Types.h`) and leaves
 * implementation classes only with query definitions. (From obvious reasons this is not
 * always possible)
 *
 * It is expected each implementation class should inherit from `with_context`
 * and provide at least table_name as static attribute.
 */

using Database = decltype(Context::db);

using CtxPtr = std::shared_ptr<Context>;
using CtxR = Context *;

// Each implementation needs to have access to the Context class, but since they are not
// owning it or copying it, raw pointer is enough.
template<typename Ctx>
struct with_context {

  with_context(CtxPtr &shared_ctx) : _ctx(shared_ctx.get()) {}
  with_context(CtxR raw_ctx) : _ctx(raw_ctx) {}

  CtxR _ctx;
};

using has_context = with_context<Context>;

struct FrameToFunc : schema::FrameToFunc, nm_impl<FrameToFunc>, has_context {
  using has_context::has_context;
};
struct BbToFunc: schema::BbToFunc, nm_impl<BbToFunc>, has_context {
  using has_context::has_context;
};

template<typename Concrete = SymbolTableEntry>
struct SymbolTableEntry_ : schema::SymbolTableEntry,
                           has_context,
                           id_based_ops_<SymbolTableEntry_<Concrete>> {
  using has_context::has_context;

  constexpr static Query q_insert =
    R"(insert into symtabs(name, module_rowid, type_rowid) values (?1, ?2, ?3))";

  constexpr static Query q_get =
    R"(select name, type_rowid from symtabs where rowid = ?1)";

  constexpr static Query s_insert_module_rowid =
    R"(insert into symtabs(name, module_rowid, type_rowid) values (?1, #1, ?2))";

};
using SymbolTableEntry_impl = SymbolTableEntry_<SymbolTableEntry>;

template<typename Concrete = MemoryRange>
struct MemoryRange_ : schema::MemoryRange,
                      has_context,
                      id_based_ops_<MemoryRange_<Concrete>>,
                      has_ea<MemoryRange_<Concrete>> {

  using has_context::has_context;

  constexpr static Query q_insert =
      R"(insert into memory_ranges(module_rowid, ea, size, bytes)
      values (?1, ?2, ?3, ?4))";

  constexpr static Query q_data =
      R"(select bytes from memory_ranges where rowid = ?1)";

  constexpr static Query q_get =
      R"(SELECT ea, size
         FROM memory_ranges
         WHERE rowid = ?1)";

  std::string_view data(int64_t id) {
    return this->_ctx->cache
           .template Find<Concrete, MemoryRange_<MemoryRange>::q_data>(id);
  }
};
using MemoryRange_impl = MemoryRange_<MemoryRange>;

template<typename Concrete = Module>
struct Module_ : schema::Module,
                 has_context,
                 id_based_ops_<Module_<Concrete>> {

  using has_context::has_context;

  constexpr static Query q_insert =
    R"(insert into modules(name) values (?1))";

  auto all_functions(int64_t id) {
    constexpr static Query q_data =
      R"(select ea, is_entrypoint from functions where module_rowid = ?1)";
    return _ctx->db.template query<q_data>(id);
  }

  auto all_functions_r(int64_t id) {
    constexpr static Query q_obj =
      R"(SELECT rowid
         FROM functions
         WHERE module_rowid = ?1)";
      return _ctx->db.template query<q_obj>(id);
  }

  auto all_blocks_r(int64_t id) {
    constexpr static Query q_bbs =
      R"(SELECT rowid
         FROM blocks
         WHERE module_rowid = ?1)";
    return _ctx->db.template query<q_bbs>(id);
  }

  auto all_symbols(int64_t id) {
    constexpr static Query q_data =
      R"(select name, type_rowid from symtabs where module_rowid = ?1)";
    return _ctx->db.template query<q_data>(id);
  }

  auto all_g_vars_r(int64_t id) {
    constexpr static Query q_obj =
      R"(SELECT rowid FROM global_variables WHERE module_rowid = ?1)";
    return _ctx->db.template query<q_obj>(id);
  }

  auto all_ext_vars_r(int64_t id) {
    constexpr static Query q_obj =
      R"(SELECT rowid FROM external_variables WHERE module_rowid = ?1)";
    return _ctx->db.template query<q_obj>(id);
  }
};
using Module_impl = Module_<Module>;

template<typename Concrete = Function>
struct Function_ : schema::Function,
                   has_context,
                   func_ops_<Function_<Concrete>>,
                   id_based_ops_<Function_<Concrete>>,
                   has_symtab_name<Function_<Concrete>>,
                   has_ea<Function_<Concrete>> {
  using has_context::has_context;
  using self_t = Function_<Function>;

  static constexpr Query q_insert =
      R"(insert into functions(module_rowid, ea, is_entrypoint) values (?1, ?2, ?3))";

  static constexpr Query q_get =
    R"(select ea, is_entrypoint from functions)";

  static constexpr Query q_bbs_r =
    R"(SELECT bb_rowid FROM function_to_block WHERE function_rowid = ?1)";

  auto BBs_r(int64_t id) {
    return _ctx->db.template query<q_bbs_r>(id);
  }
};
using Function_impl = Function_<Function>;


template<typename Self>
struct bb_mixin : id_based_ops_<Self>,
                  has_ea<Self>{};

template<typename Concrete = BasicBlock>
struct BasicBlock_: schema::BasicBlock,
                    has_context,
                    bb_mixin<BasicBlock_<Concrete>> {
  using has_context::has_context;

  constexpr static Query q_insert =
    R"(insert into blocks(module_rowid, ea, size, memory_rowid)
        values (?1, ?2, ?3, ?4))";

  constexpr static Query q_get =
    R"(SELECT ea, size
       FROM blocks
       WHERE rowid = ?1)";

  constexpr static Query q_orphans =
    R"(SELECT bb.rowid
       FROM blocks AS bb
       WHERE bb.rowid NOT IN (SELECT bb_rowid
                              FROM function_to_block))";

  constexpr static Query q_iter_code_xrefs =
    R"(SELECT cr.rowid
       FROM code_references AS cr
       WHERE cr.bb_rowid = ?1)";

  // TODO: This is dependent on internals of code_references table
  constexpr static Query q_iter_code_xrefs_d =
    R"(SELECT cr.ea, cr.target_ea, cr.operand_type_rowid, cr.mask
       FROM code_references AS cr
       WHERE cr.bb_rowid = ?1)";

  constexpr static Query q_iter_succs =
    R"(SELECT to_rowid
       FROM bb_successors
       WHERE from_rowid = ?1)";

  constexpr static Query q_add_succ =
    R"(INSERT INTO bb_successors(from_rowid, to_rowid) VALUES (?1, ?2))";

  constexpr static Query q_remove_all_succ =
    R"(DELETE FROM bb_successors WHERE from_rowid = ?1)";

  constexpr static Query q_remove_specific_succ =
    R"(DELETE FROM bb_successors WHERE from_rowid = ?1 AND to_rowid = ?2)";

  auto Succs(int64_t id) {
    return _ctx->db.template query<q_iter_succs>(id);
  }

  auto RemoveSucc(int64_t from, int64_t to) {
    return _ctx->db.template query<q_remove_specific_succ>(from, to);
  }

  auto RemoveSuccs(int64_t from) {
    return _ctx->db.template query<q_remove_all_succ>(from);
  }

  auto AddSucc(int64_t from, int64_t to) {
    return _ctx->db.template query<q_add_succ>(from, to);
  }

  auto CodeXrefs(int64_t id) {
    return _ctx->db.template query<q_iter_code_xrefs_d>(id);
  }

  auto CodeXrefs_r(int64_t id) {
    return _ctx->db.template query<q_iter_code_xrefs>(id);
  }

  auto orphaned() {
    return _ctx->db.template query<q_orphans>();
  }

  std::string_view data(int64_t id) {
    // SUBSTR index starts from 0, therefore we need + 1
    constexpr static Query q_data =
      R"(SELECT mr.rowid, bb.ea - mr.ea FROM
          blocks as bb JOIN
          memory_ranges as mr ON
          mr.rowid = bb.memory_rowid and bb.rowid = ?1)";
   int64_t mr_rowid;
   uint64_t offset;
    std::tie(mr_rowid, offset) = *this->_ctx->db.template query<q_data>(id)
                                                .template Get<int64_t, uint64_t>();
    auto c_data = this->_ctx->cache
                  .template Find<MemoryRange, MemoryRange_<MemoryRange>::q_data>(mr_rowid);
    return c_data.substr(offset);
  }
};
using BasicBlock_impl = BasicBlock_<BasicBlock>;


template<typename Concrete = Segment>
struct Segment_ : schema::Segment,
                  has_context,
                  id_based_ops_<Segment_<Concrete>>,
                  has_ea<Segment_<Concrete>> {
  using has_context::has_context;

  constexpr static Query q_insert =
    R"(insert into segments(
        ea, size,
        read_only, is_external, is_exported, is_thread_local,
        variable_name, memory_rowid) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8))";

  constexpr static Query q_get =
    R"(SELECT ea, size, read_only, is_external, is_exported, is_thread_local
       FROM segments
       WHERE rowid = ?1)";

  constexpr static Query q_get_module =
    R"(SELECT mr.module_rowid
       FROM segments as seg
       JOIN memory_ranges AS mr
       WHERE seg.memory_rowid = mr.rowid and seg.rowid = ?1)";

  constexpr static Query q_id_from_ea =
    R"(SELECT seg.rowid
       FROM segments as seg
       JOIN memory_ranges AS mr
       WHERE seg.memory_rowid = mr.rowid and seg.ea = ?1 and mr.module_rowid = ?2)";

  auto _insert(uint64_t ea,
               uint64_t size,
               const typename Concrete::Flags &flags,
               const std::string &name,
               int64_t memory_rowid) {

    return this->insert(ea, size,
                        flags.read_only, flags.is_external, flags.is_exported,
                        flags.is_thread_local,
                        name, memory_rowid);
  }


  std::string_view data(int64_t id) {
    constexpr static Query q_data =
      R"(SELECT mr.rowid, s.ea - mr.ea, s.size FROM
          segments as s JOIN
          memory_ranges as mr ON
          mr.rowid = s.memory_rowid and s.rowid = ?1)";
    int64_t mr_rowid;
    uint64_t offset,
             size;
    std::tie(mr_rowid, offset, size) =
      *this->_ctx->db.template query<q_data>(id)
                 .template Get<int64_t, uint64_t, uint64_t>();
    auto c_data = this->_ctx->cache
                  .template Find<MemoryRange, MemoryRange_<MemoryRange>::q_data>(mr_rowid);
    return c_data.substr(offset, size);
  }

  void SetFlags(int64_t id, const typename Concrete::Flags &flags) {
    constexpr static Query q_set_flags =
      R"(UPDATE segments SET
        (read_only, is_external, is_exported, is_thread_local) =
        (?2, ?3, ?4, ?5) WHERE rowid = ?1)";
    this->_ctx->db.template query<q_set_flags>(id,
                                    flags.read_only, flags.is_external,
                                    flags.is_exported, flags.is_thread_local);
  }
};
using Segment_impl = Segment_<Segment>;


template<typename Concrete = CodeXref>
struct CodeXref_ : schema::CodeXref,
                   has_context,
                   has_symtab_name<CodeXref_<Concrete>>,
                   has_ea<CodeXref_<Concrete>>,
                   id_based_ops_<CodeXref_<Concrete>> {
  using has_context::has_context;

  constexpr static Query q_insert =
    R"(insert into code_references(
         ea, target_ea, bb_rowid, operand_type_rowid, mask, symtab_rowid)
       values(?1, ?2, ?3, ?4, ?5, ?6))";

  constexpr static Query q_get_module_rowid =
    R"(SELECT mr.module_rowid FROM data_references as dr
                              JOIN segments as seg
                              JOIN memory_ranges as mr
                              ON dr.segment_rowid = seg.rowid
                                 and seg.memory_rowid = mr.rowid)";

  constexpr static Query q_get =
    R"(SELECT ea, target_ea, operand_type_rowid, mask
       FROM code_references
       WHERE rowid = ?1)";
};
using CodeXref_impl = CodeXref_<CodeXref>;

template<typename Concrete = DataXref>
struct DataXref_ : schema::DataXref,
                   has_context,
                   has_symtab_name<DataXref_<Concrete>>,
                   has_ea<DataXref_<Concrete>>,
                   id_based_ops_<DataXref_<Concrete>> {

  using has_context::has_context;

  constexpr static Query q_insert =
    R"(insert into data_references(
          ea, width, target_ea, segment_rowid, fixup_kind_rowid, symtab_rowid)
       values(?1, ?2, ?3, ?4, ?5, ?6))";

  constexpr static Query q_get =
    R"(SELECT ea, width, target_ea, fixup_kind_rowid
       FROM data_references
       WHERE rowid = ?1)";
};
using DataXref_impl = DataXref_<DataXref>;

template<typename Concrete = ExternalFunction>
struct ExternalFunction_ : schema::ExternalFunction,
                           has_context,
                           has_symtab_name<ExternalFunction_<Concrete>>,
                           has_ea<ExternalFunction_<Concrete>>,
                           id_based_ops_<ExternalFunction_<Concrete>> {
  using has_context::has_context;

  constexpr static Query q_insert =
    R"(insert into external_functions(
        ea, calling_convention_rowid, symtab_rowid, module_rowid, has_return, is_weak)
        values (?1, ?2, ?3, ?4, ?5, ?6))";

  constexpr static Query q_get =
    R"(SELECT ea, calling_convention_rowid, has_return, is_weak
       FROM external_functions
       WHERE rowid = ?1)";

};
using ExternalFunction_impl = ExternalFunction_<ExternalFunction>;

template<typename Concrete = GlobalVar>
struct GlobalVar_ : schema::GlobalVar,
                    has_context,
                    has_ea<GlobalVar_<GlobalVar>>,
                    id_based_ops_<GlobalVar_<GlobalVar>> {

  using has_context::has_context;

  constexpr static Query q_insert =
    R"(INSERT INTO global_variables(ea, name, size, module_rowid)
              VALUES(?1, ?2, ?3, ?4))";

  constexpr static Query q_get =
    R"(SELECT ea, name, size FROM global_variables WHERE rowid = ?1)";
};
using GlobalVar_impl = GlobalVar_<GlobalVar>;

template<typename Conrete = ExternalVar>
struct ExternalVar_ : schema::ExternalVar,
                      has_context,
                      has_ea<ExternalVar_<ExternalVar>>,
                      id_based_ops_<ExternalVar_<ExternalVar>> {

  using has_context::has_context;

  constexpr static Query q_insert =
    R"(INSERT INTO external_variables(ea, name, size, is_weak, is_thread_local, module_rowid)
              VALUES(?1, ?2, ?3, ?4, ?5, ?6))";

  constexpr static Query q_get =
    R"(SELECT ea, name, size, is_weak, is_thread_local
              FROM external_variables WHERE rowid = ?1)";
};
using ExternalVar_impl = ExternalVar_<ExternalVar>;

template<typename Concrete=ExceptionFrame>
struct ExceptionFrame_ : schema::ExceptionFrame,
                         has_context,
                         id_based_ops_<ExceptionFrame_<ExceptionFrame>> {

  using has_context::has_context;

  constexpr static Query q_insert =
    R"(INSERT INTO exception_frames(start_ea, end_ea, lp_ea, action_rowid)
              VALUE(?1, ?2, ?3, ?4))";

  constexpr static Query q_get =
    R"(SELECT start_ea, end_ea, lp_ea, action_rowid FROM exception_frames
              WHERE rowid = ?1)";

};
using ExceptionFrame_impl = ExceptionFrame_<ExceptionFrame>;


/* Hardcoding each implementation class in each public object method implementation
 * is tedious and error-prone. Following class provides this mapping at compile time
 * and tries to eliminate as much copy-paste code as possible. */
template<typename T>
struct dispatch {
  using type = void;
};

/* Each specialization should have:
 * T = public API class
 * type = implementation class
 * data_fields = util::TypeList<...> where ... should be types of attributes of T::data_t.
 *               This is used to allowed easier code generation for DB -> T::data_t
 *
 * TODO: If tables are defined as templates table type should be here as well
 */

template<>
struct dispatch<ExternalFunction> {
  using type = ExternalFunction_<ExternalFunction>;
  using data_fields = util::TypeList<uint64_t, CallingConv, bool, bool>;
};

template<>
struct dispatch<CodeXref> {
  using type = CodeXref_<CodeXref>;
  using data_fields =
    util::TypeList<uint64_t, uint64_t, OperandType, std::optional<int64_t>>;
};

template<>
struct dispatch<DataXref> {
  using type = DataXref_<DataXref>;
  using data_fields = util::TypeList<uint64_t, uint64_t, uint64_t, FixupKind>;
};

template<>
struct dispatch<Function> {
  using type = Function_<Function>;
  using data_fields = util::TypeList<uint64_t, bool>;
};

template<>
struct dispatch<BasicBlock> {
  using type = BasicBlock_<BasicBlock>;
  using data_fields = util::TypeList<uint64_t, uint64_t>;
};

template<>
struct dispatch<Segment> {
  using type = Segment_<Segment>;
  using data_fields = util::TypeList<uint64_t, uint64_t, bool, bool, bool, bool>;
};

template<>
struct dispatch<MemoryRange> {
  using type = MemoryRange_<MemoryRange>;
  using data_fields = util::TypeList<uint64_t, uint64_t>;
};

template<>
struct dispatch<SymbolTableEntry> {
  using type = SymbolTableEntry_<SymbolTableEntry>;
  using data_fields = util::TypeList<std::string, SymbolVisibility>;
};

template<>
struct dispatch<GlobalVar> {
  using type = GlobalVar_<GlobalVar>;
  using data_fields = util::TypeList<uint64_t, std::string, uint64_t>;
};

template<>
struct dispatch<ExternalVar> {
  using type = ExternalVar_<ExternalVar>;
  using data_fields = util::TypeList<uint64_t, std::string, uint64_t, bool, bool>;
};

template<typename T>
using remove_cvp_t = typename std::remove_cv_t<std::remove_pointer_t<T>>;

template<typename T>
using impl_t = typename dispatch<remove_cvp_t<T>>::type;

template<typename T>
using data_fields_t = typename dispatch<remove_cvp_t<T>>::data_fields;

// Helper to ease some writing
template<typename Self, typename Ctx>
auto Impl(Self, Ctx ctx) {
  return impl_t<Self>(ctx);
}

// Convert result of `query` into `Concrete`
// This is used by Iterators
template<typename Concrete, typename Result, typename ... Fields>
auto MaybeToData(Result &result, util::TypeList<Fields...>) {
  auto out = result.template Get<Fields...>();
  return util::maybe_to_struct<Concrete>(std::move(out));
}

template<typename Concrete, typename Result, typename ... Fields>
auto ToData(Result &result, util::TypeList<Fields...>) {
  auto out = result.template Get<Fields...>();
  return util::to_struct<Concrete>(std::move(out));
}

/* Definition of Iterators (their hidden part) */
namespace details {

// Data iterator returns data_t
struct DataIterator_impl {
  using Result_t = Context::Result_t;
  Result_t result;

  DataIterator_impl(Result_t &&r) : result(std::move(r)) {}

  template<typename Entry>
  auto Fetch() {
    return MaybeToData<typename Entry::data_t>(result, data_fields_t<Entry>{}) ;
  }
};

// Object Iterator returns public API objects
struct ObjectIterator_impl {
  using Result_t = Context::Result_t;
  Result_t result;
  CtxPtr ctx;

  ObjectIterator_impl(Result_t &&r, CtxPtr ctx_)
    : result(std::move(r)),
      ctx(std::move(ctx_))
  {}


  template<typename Object>
  auto Fetch() -> std::optional<Object> {
    return Build<Object>();
  }

  template<typename Object>
  auto Build() -> std::optional<Object> {
    if (auto id = result.template GetScalar<int64_t>()) {
      return { Object{ *id, ctx } };
    }
    return {};
  }
};

} // namespace details

/* Define methods of iterators visible from header */
template<typename Entry>
WeakDataIterator<Entry>::WeakDataIterator(Impl_t &&init) : impl(std::move(init)) {}

template<typename Entry>
auto WeakDataIterator<Entry>::Fetch() -> maybe_data_t {
  return impl->Fetch<Entry>();
}

template<typename Entry>
WeakDataIterator<Entry>::~WeakDataIterator() {}

template<typename Entry>
WeakObjectIterator<Entry>::WeakObjectIterator(Impl_t &&init) : impl(std::move(init)) {}

template<typename Entry>
auto WeakObjectIterator<Entry>::Fetch() -> maybe_data_t {
  return impl->Fetch<data_t>();
}

template<typename Entry>
WeakObjectIterator<Entry>::~WeakObjectIterator() {}



// TODO: Use `impl_t` in methods defined before it was present.
/* Define public API methods, typically by calling their implementations */

/* Letter */

Letter::Letter(const std::string &name) : _ctx(std::make_shared<Context>(name)) {}

void Letter::CreateSchema()
{
  constexpr static Query q_pragmas =
    R"(PRAGMA foreign_keys = ON)";
  _ctx->db.template query<q_pragmas>();
  Schema::CreateSchema(*_ctx);
}

Module Letter::AddModule(const std::string &name) {
  return { Module_{ _ctx }.insert(name), _ctx };
}

Function Letter::AddFunction(const Module &module, uint64_t ea, bool is_entrypoint)
{
  return { Function_{ _ctx }.insert(module._id, ea, is_entrypoint), _ctx };
}

BasicBlock Letter::AddBasicBlock(const Module &module,
                                 uint64_t ea,
                                 uint64_t size,
                                 const MemoryRange &range)
{
  return { BasicBlock_{ _ctx }.insert(module._id, ea, size, range._id), _ctx };
}

MemoryRange Letter::AddMemoryRange(const Module &module,
                                   uint64_t ea,
                                   uint64_t size,
                                   std::string_view data) {
  // TODO: Check if this copy to sqlite::blob is required
  return { MemoryRange_{ _ctx }.insert(module._id, ea, size,
                                 sqlite::blob(data.begin(), data.end())),
            _ctx };
}

MemoryRange Letter::AddMemoryRange(const Module &module,
                                   uint64_t ea,
                                   std::string_view data) {
  return AddMemoryRange(module, ea, data.size(), data);
}

/* Module */

Function Module::AddFunction(uint64_t ea, bool is_entrypoint) {
  return { Function_{ _ctx }.insert(_id, ea, is_entrypoint), _ctx };
}

MemoryRange Module::AddMemoryRange(uint64_t ea, uint64_t size, std::string_view data) {
  // TODO: Check if this copy to sqlite::blob is required
  return { MemoryRange_{ _ctx }.insert(_id, ea, size,
                                 sqlite::blob(data.begin(), data.end())),
           _ctx };
}

MemoryRange Module::AddMemoryRange(uint64_t ea, std::string_view data) {
  return AddMemoryRange(ea, data.size(), data);
}

BasicBlock Module::AddBasicBlock(uint64_t ea, uint64_t size, const MemoryRange &mem) {
  return { BasicBlock_{ _ctx }.insert(_id, ea, size, mem._id), _ctx };
}

SymbolTableEntry Module::AddSymbolTableEntry(const std::string &name,
                                             SymbolVisibility type) {
  return { SymbolTableEntry_{ _ctx }.insert(name, _id, static_cast<unsigned char>(type)),
           _ctx };
}

ExternalFunction Module::AddExternalFunction(uint64_t ea,
                                             const SymbolTableEntry &name,
                                             CallingConv cc,
                                             bool has_return, bool is_weak) {
  return { ExternalFunction_{ _ctx }.insert(ea,
                                            static_cast<unsigned char>(cc),
                                            name._id,
                                            _id,
                                            has_return,
                                            is_weak),
           _ctx };
}

GlobalVar Module::AddGlobalVar(uint64_t ea, const std::string &name, uint64_t size) {
  return { impl_t<GlobalVar>(_ctx).insert( ea, name, size, _id ), _ctx };
}

ExternalVar Module::AddExternalVar(uint64_t ea, const std::string &name, uint64_t size,
                                   bool is_weak, bool is_thread_local) {
  return { impl_t<ExternalVar>(_ctx).insert(ea, name, size,
                                            is_weak, is_thread_local, _id),
           _ctx };
}

WeakObjectIterator<BasicBlock> Module::OrphanedBasicBlocks() {
  auto result = BasicBlock_{ _ctx }.orphaned();
  return { std::make_unique<details::ObjectIterator_impl>(std::move(result), _ctx) };
}

WeakObjectIterator<BasicBlock> Module::Blocks() {
  auto result = Module_{ _ctx }.all_blocks_r(_id);
  return { std::make_unique<details::ObjectIterator_impl>(std::move(result), _ctx) };
}

WeakDataIterator<SymbolTableEntry> Module::SymbolsData() {
  auto result = Module_{_ctx }.all_symbols(_id);
  return { std::make_unique<details::DataIterator_impl>(std::move(result)) };
}

WeakObjectIterator<Function> Module::Functions() {
  auto result = Module_{ _ctx }.all_functions_r(_id);
  return { std::make_unique<details::ObjectIterator_impl>(std::move(result), _ctx) };
}

WeakObjectIterator<GlobalVar> Module::GlobalVars() {
  auto result = Module_{ _ctx }.all_g_vars_r(_id);
  return { std::make_unique<details::ObjectIterator_impl>(std::move(result), _ctx) };
}

WeakObjectIterator<ExternalVar> Module::ExternalVars() {
  auto result = Module_{ _ctx }.all_ext_vars_r(_id);
  return { std::make_unique<details::ObjectIterator_impl>(std::move(result), _ctx) };
}

/* Function */

void Function::DeattachBlock(const BasicBlock &bb) {
  BbToFunc( _ctx ).UnbindFrom<Function_impl>(_id, bb._id);
}

void Function::AttachBlock(const BasicBlock &bb) {
  BbToFunc( _ctx ).BindTo<Function_impl>(_id, bb._id);
}

WeakObjectIterator<BasicBlock> Function::BasicBlocks() {
  auto result = Impl(*this, _ctx).BBs_r(_id);
  return { std::make_unique<details::ObjectIterator_impl>(std::move(result), _ctx) };
}

/* BasicBlock */
std::string_view BasicBlock::Data() {
    return BasicBlock_{ _ctx }.data(_id);
}

CodeXref BasicBlock::AddXref(uint64_t ea, uint64_t target_ea, OperandType op_type) {
  return { CodeXref_{ _ctx }.insert(ea,
                                    target_ea,
                                    _id,
                                    static_cast<unsigned char>(op_type),
                                    nullptr,
                                    nullptr),
          _ctx };
}


CodeXref BasicBlock::AddXref(uint64_t ea,
                             uint64_t target_ea,
                             OperandType op_type,
                             const SymbolTableEntry &name,
                             std::optional<int64_t> mask) {
  if (!mask) {
    return { CodeXref_{ _ctx }.insert(ea,
                                      target_ea,
                                      _id,
                                      static_cast<unsigned char>(op_type),
                                      nullptr,
                                      name._id),
            _ctx };
  }
  return { CodeXref_{ _ctx }.insert(ea,
                                    target_ea,
                                    _id,
                                    static_cast<unsigned char>(op_type),
                                    *mask,
                                    name._id),
          _ctx };
}

void BasicBlock::AddSucc(const BasicBlock& bb) {
  Impl(*this, _ctx).AddSucc(_id, bb._id);
}

void BasicBlock::RemoveSucc(const BasicBlock &bb) {
  Impl(*this, _ctx).RemoveSucc(_id, bb._id);
}

void BasicBlock::RemoveSuccs() {
  Impl(*this, _ctx).RemoveSuccs(_id);
}

WeakDataIterator<CodeXref> BasicBlock::CodeXrefsData() {
  auto result = Impl(*this, _ctx).CodeXrefs(_id);
  return { std::make_unique<details::DataIterator_impl>(std::move(result)) };
}


WeakObjectIterator<CodeXref> BasicBlock::CodeXrefs() {
  auto result = Impl(*this, _ctx).CodeXrefs_r(_id);
  return { std::make_unique<details::ObjectIterator_impl>(std::move(result), _ctx) };
}

WeakObjectIterator<BasicBlock> BasicBlock::Succs() {
  auto result = BasicBlock_{ _ctx }.Succs(_id);
  return { std::make_unique<details::ObjectIterator_impl>(std::move(result), _ctx) };
}
/* Segment */

std::string_view Segment::Data() {
  return Segment_(_ctx).data(_id);
}

void Segment::SetFlags(const Flags &flags) {
  return Segment_{ _ctx }.SetFlags(_id, flags);
}

DataXref Segment::AddXref(uint64_t ea, uint64_t target_ea,
                          uint64_t width, FixupKind fixup) {
  return { DataXref_{ _ctx }.insert(ea, width, target_ea, _id,
                                    static_cast<unsigned char>(fixup),
                                    nullptr),
          _ctx };
}

DataXref Segment::AddXref(uint64_t ea, uint64_t target_ea,
                          uint64_t width, FixupKind fixup, const SymbolTableEntry &name) {

  return { DataXref_{ _ctx }.insert(ea, width, target_ea, _id,
                                    static_cast<unsigned char>(fixup),
                                    name._id),
         _ctx };
}



/* MemoryRange */

Segment MemoryRange::AddSegment(uint64_t ea,
                                uint64_t size,
                                const Segment::Flags &flags,
                                const std::string &name) {
  return { Segment_{ _ctx }._insert(ea, size, flags, name, _id), _ctx };
}

std::string_view MemoryRange::Data() {
  return impl_t<decltype(this)>{ _ctx }.data(_id);
}

/* CodeXref */

/* ExternalFunction */

std::string ExternalFunction::Name() const {
  return *impl_t<decltype(this)>{ _ctx }.GetName(_id);
}

/* GlobalVar */


// Thanks to uniform dispatch each definition of following method looks identical,
// therefore simple macro can be defined that is more readable.

/* operator*() */

#define DEFINE_DATA_OPERATOR(Type) \
  Type::data_t Type::operator*() const { \
    using self_t = remove_cvp_t<decltype(this)>; \
    return impl_t<self_t>{_ctx} \
        .c_get<typename self_t::data_t>(_id, data_fields_t<self_t>{}); \
  }

DEFINE_DATA_OPERATOR(SymbolTableEntry);
DEFINE_DATA_OPERATOR(ExternalFunction);
DEFINE_DATA_OPERATOR(BasicBlock);
DEFINE_DATA_OPERATOR(Function);
DEFINE_DATA_OPERATOR(Segment);
DEFINE_DATA_OPERATOR(MemoryRange);
DEFINE_DATA_OPERATOR(CodeXref);
DEFINE_DATA_OPERATOR(DataXref);
DEFINE_DATA_OPERATOR(GlobalVar);
DEFINE_DATA_OPERATOR(ExternalVar);

/* Erasable */

#define DEF_ERASE(self) \
  void self::Erase() { \
    impl_t<decltype(this)>{_ctx}.erase(_id); \
  }

DEF_ERASE(BasicBlock)
DEF_ERASE(SymbolTableEntry)
DEF_ERASE(ExternalFunction)
DEF_ERASE(Function)
DEF_ERASE(Segment)
DEF_ERASE(MemoryRange)
DEF_ERASE(CodeXref)
DEF_ERASE(DataXref)
DEF_ERASE(GlobalVar)
DEF_ERASE(ExternalVar)

#undef DEF_ERASE

/* In public API some classes inherit from interfaces, that are CRTP.
 * Therefore it is enough to define them once, but since they are templates we need
 * to explicitly instantiate them. That is luckily not a problem, since we know
 * before-hand which classes implements which interface and user is not allowed to define
 * any new classes.
 */

template<typename Self>
uint64_t interface::HasEa<Self>::ea() {
  auto self = static_cast<Self *>(this);
  return impl_t<decltype(self)>{ self->_ctx }.get_ea(self->_id);
}

template<typename Self>
std::optional<std::string> interface::HasSymbolTableEntry<Self>::Name() {
  auto self = static_cast<Self *>(this);
  return impl_t<decltype(self)>{ self->_ctx }.GetName(self->_id);
}

template<typename Self>
void interface::HasSymbolTableEntry<Self>::Name(
    const SymbolTableEntry &name) {

  auto self = static_cast<Self *>(this);
  return impl_t<decltype(self)>{ self->_ctx }.Name(self->_id, name._id);
}

template<typename Self>
std::optional<SymbolTableEntry::data_t> interface::HasSymbolTableEntry<Self>::Symbol() {
  auto self = static_cast<Self *>(this);

  auto res = impl_t<decltype(self)>{self->_ctx}.Symbol(self->_id);
  return util::maybe_to_struct<SymbolTableEntry::data_t>(
      res.template Get<std::string, SymbolVisibility>());
}

template<typename Self>
std::optional<Self> interface::HasEa<Self>::MatchEa(
    details::CtxPtr &ctx_ptr,
    int64_t module_id,
    uint64_t ea) {

  if (auto res = impl_t<Self>{ctx_ptr}.IdFromEa(ea, module_id)) {
    return { Self(*res, ctx_ptr) };
  }
  return {};
}

template<typename Self>
Module interface::HasEa<Self>::Module() {
  auto self = static_cast<Self *>(this);
  return { impl_t<Self>{self->_ctx}.GetModule(self->_id), self->_ctx };
}

// TODO: Move into separate .cpp file

namespace interface {

/* We must explicitly instantiate all templates */

template struct HasEa<DataXref>;
template struct HasSymbolTableEntry<DataXref>;

template struct HasEa<MemoryRange>;

template struct HasEa<Segment>;
// TODO: Implement
//template struct HasSymbolTableEntry<Segment>;

template struct HasEa<Function>;
template struct HasSymbolTableEntry<Function>;

template struct HasEa<BasicBlock>;

template struct HasEa<ExternalFunction>;
template struct HasSymbolTableEntry<ExternalFunction>;

template struct HasEa<CodeXref>;
template struct HasSymbolTableEntry<CodeXref>;

template struct HasEa<GlobalVar>;

template struct HasEa<ExternalVar>;
} // namespace interface

// Since Iterators are also templated, we must instantiate them as well

template struct WeakObjectIterator<GlobalVar>;

template struct WeakObjectIterator<ExternalVar>;

template struct WeakDataIterator<SymbolTableEntry>;

template struct WeakObjectIterator<Function>;
template struct WeakObjectIterator<BasicBlock>;

template struct WeakDataIterator<CodeXref>;
template struct WeakObjectIterator<CodeXref>;

} // namespace cfg
} // namespace mcsema
