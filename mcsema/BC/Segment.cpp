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

#include "mcsema/BC/Segment.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wswitch-enum"
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#pragma clang diagnostic pop

#include <remill/Arch/Arch.h>
#include <remill/BC/Compat/GlobalValue.h>
#include <remill/BC/Util.h>

#include <algorithm>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Callback.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

DEFINE_string(libc_constructor, "",
              "Constructor function for running pre-`main` initializers. This "
              "is a (lifted) function that will be executed before the `main` "
              "function is executed. This feature should be used when lifting "
              "code compiled from C++ programs. Many C++ programs will "
              "construct global objects before the `main` function is executed,"
              " and those constructors will be called via a function like "
              "`__libc_csu_init` (on GNU-based systems).");

DEFINE_string(libc_destructor, "",
              "Destructor function for running post-`main` finalizers. This "
              "is a (lifted) function that will be executed after the `main` "
              "function returns. For example, on GNU-based systems, this is "
              "typically `__libc_csu_fini`.");

DEFINE_bool(force_embed_data_refs, false,
            "Should data-to-code and data-to-data cross-references be force-"
            "embedded within data segments? This is a good option to enable "
            "when using McSema-produced bitcode in KLEE, as it avoids doing "
            "lazy cross-reference initialization.");

DEFINE_bool(name_lifted_sections, false,
            "Put lifted sections into sections in the target in a way that is "
            "reflective of their original addresses.");

DECLARE_bool(disable_aliases);

DEFINE_bool(merge_segments, false, "Should all lifted segments be merged?");

namespace mcsema {
namespace {

// Lets us decide if we can use a constant aggregate zero value, i.e.
// direct LLVM to put this data into the `.bss` segment.
static bool IsZero(const NativeSegment *cfg_seg) {
  for (const auto &cfg_seg_entry : cfg_seg->entries) {
    const auto &entry = cfg_seg_entry.second;
    if (!entry.blob || !entry.blob->is_zero) {
      return false;
    }
  }
  return true;
}

// The type of the segment is a packed structure that is a sequence of opaque
// byte arrays, interspersed with cross-references, which will be represented
// as (pointers casted to) integers.
static llvm::StructType *GetSegmentType(const NativeSegment *cfg_seg) {
  std::stringstream ss;
  ss << cfg_seg->lifted_name << "_type";
  const auto type_name = ss.str();

  auto seg_type = gModule->getTypeByName(type_name);
  if (seg_type) {
    return seg_type;
  }

  std::vector<llvm::Type *> entry_types;

  auto byte_type = llvm::Type::getInt8Ty(*gContext);

  if (cfg_seg->padding) {
    auto arr_type = llvm::ArrayType::get(byte_type, cfg_seg->padding);
    entry_types.push_back(arr_type);
  }

  for (const auto &cfg_seg_entry : cfg_seg->entries) {
    const auto &entry = cfg_seg_entry.second;
    if (entry.blob) {
      auto arr_type = llvm::ArrayType::get(byte_type, entry.blob->size);
      entry_types.push_back(arr_type);

    } else if (entry.xref) {
      const auto entry_size = entry.xref->width * 8;
      if (entry_size == gArch->address_size) {
        entry_types.push_back(llvm::Type::getInt8PtrTy(*gContext, 0));
      } else {
        entry_types.push_back(llvm::Type::getIntNTy(
            *gContext, static_cast<unsigned>(entry_size)));
      }

    } else {
      LOG(FATAL) << "Missing blob or xref segment entry value for segment "
                 << cfg_seg->name << " data at " << std::hex << entry.ea;
    }
  }

  seg_type = llvm::StructType::create(entry_types, type_name, true);
  CHECK(nullptr != seg_type)
      << "Unable to create structure type for segment " << cfg_seg->name
      << " beginning at " << std::hex << cfg_seg->ea;

  llvm::DataLayout data_layout(gModule.get());
  auto seg_size = data_layout.getTypeAllocSize(seg_type);
  CHECK_EQ(seg_size, (cfg_seg->size + cfg_seg->padding))
      << "Size of structure type of segment " << cfg_seg->name << " is "
      << seg_size << " but was expected to be " << cfg_seg->size;

  return seg_type;
}

static llvm::GlobalValue::ThreadLocalMode
ThreadLocalMode(const NativeObject *cfg_obj) {
  if (cfg_obj->is_thread_local) {
    return llvm::GlobalValue::InitialExecTLSModel;
  } else {
    return llvm::GlobalValue::NotThreadLocal;
  }
}

// Create a McSema-specific constructor/destructor function, and add it to the
// corresponding LLVM-specific array.
static llvm::Function *CreateMcSemaInitFiniImpl(const char *func_name,
                                                const char *arr_name) {
  LOG(INFO) << "Creating " << func_name << " function to initialize runtime.";

  auto func = llvm::Function::Create(
      llvm::FunctionType::get(llvm::Type::getVoidTy(*gContext), false),
      llvm::GlobalValue::InternalLinkage, func_name, gModule.get());

  auto bool_type = llvm::Type::getInt1Ty(*gContext);
  auto check_var = new llvm::GlobalVariable(bool_type, false,
                                            llvm::GlobalValue::InternalLinkage);
  check_var->setInitializer(llvm::Constant::getNullValue(bool_type));

  auto entry = llvm::BasicBlock::Create(*gContext, "", func);
  llvm::IRBuilder<> ir(entry);
  ir.CreateRetVoid();

  auto i32_type = llvm::Type::getInt32Ty(*gContext);
  auto ptr_type = llvm::Type::getInt8PtrTy(*gContext);

  // Type of an entry in the init/fini array.
  std::vector<llvm::Type *> element_types;
  element_types.push_back(i32_type);
  element_types.push_back(func->getType());
  element_types.push_back(ptr_type);
  auto el_type = llvm::StructType::get(*gContext, element_types);

  // Init/fini array entry.
  std::vector<llvm::Constant *> element_inits;
  element_inits.push_back(llvm::ConstantInt::get(i32_type, 101));
  element_inits.push_back(func);
  element_inits.push_back(llvm::Constant::getNullValue(ptr_type));
  auto el_init = llvm::ConstantStruct::get(el_type, element_inits);

  std::vector<llvm::Constant *> new_elems;

  auto global_ctors = gModule->getGlobalVariable(arr_name);
  if (global_ctors) {
    LOG(INFO) << "Module already has a " << arr_name << " array.";

    auto arr =
        llvm::dyn_cast<llvm::ConstantArray>(global_ctors->getInitializer());
    auto num_ops = arr->getNumOperands();
    for (auto i = 0U; i < num_ops; ++i) {
      new_elems.push_back(arr->getOperand(i));
    }
  }

  new_elems.push_back(el_init);

  auto arr_type = llvm::ArrayType::get(el_type, new_elems.size());
  auto arr_init = llvm::ConstantArray::get(arr_type, new_elems);
  auto arr =
      new llvm::GlobalVariable(*gModule, arr_type, false /* isConstant */,
                               llvm::GlobalVariable::AppendingLinkage, arr_init,
                               global_ctors ? "__mcsema.temp_array" : arr_name);

  if (global_ctors) {
    arr->takeName(global_ctors);
    global_ctors->dropAllReferences();
    global_ctors->eraseFromParent();
  }

  return func;
}

static llvm::Function *GetOrCreateMcSemaConstructor(void) {
  static llvm::Function *gInitFunc = nullptr;
  if (gInitFunc) {
    return gInitFunc;
  }

  gInitFunc =
      CreateMcSemaInitFiniImpl("__mcsema_constructor", "llvm.global_ctors");

  return gInitFunc;
}

static llvm::Function *GetOrCreateMcSemaDestructor(void) {
  static llvm::Function *gFiniFunc = nullptr;
  if (!gFiniFunc) {
    gFiniFunc =
        CreateMcSemaInitFiniImpl("__mcsema_destructor", "llvm.global_dtors");
  }
  return gFiniFunc;
}

// Add code to the `__mcsema_constructor` function to lazily (i.e. at runtime)
// initialize the value of a cross-reference.
//
// Consider the following C code:
//
//    FILE *gFilePtr = stdout;
//
// The type of `gFilePtr` is a `FILE **`, and it will show up as such in
// the bitcode. `stdout` is an extern, and its initializer is not present.
// What a compiler does in this case is allocate space for `gFilePtr` in the
// `.bss` section, and produces some actual code that runs as a constructor
// function that initializes the actual pointer at runtime before `main` is
// executed.
//
// Sometimes IDA picks up on these types of references, and so we need to
// handle them by emulating this runtime initialization. We create a special
// constructor function of our own, `__mcsema_constructor`, that will contain
// code that can do these initializations.
static void LazyInitXRef(const NativeXref *xref,
                         llvm::Constant *target_addr_const) {
  auto init_func = GetOrCreateMcSemaInitializer();
  llvm::BasicBlock *block = &init_func->back();
  llvm::IRBuilder<> ir(block);
  ir.SetInsertPoint(&block->front());

  if (xref->segment->is_external) {
    LOG(ERROR) << "Ignoring lazy initialization of cross-reference to "
               << std::hex << xref->target_ea << " at " << xref->ea
               << " in external segment '" << xref->segment->name << "' at "
               << xref->segment->ea << std::dec;
    return;
  }

  auto seg = llvm::dyn_cast<llvm::GlobalVariable>(xref->segment->Pointer());
  if (seg->isConstant()) {
    LOG(WARNING) << "Marking " << seg->getName().str() << " as non-constant to "
                 << "support lazy initialization of reference to " << std::hex
                 << xref->target_ea << " from " << xref->ea << std::dec;
    seg->setConstant(false);
  }

  if (target_addr_const->isNullValue()) {
    return;
  }

  llvm::Value *target_addr = target_addr_const;

  switch (xref->fixup_kind) {
    case NativeXref::kAbsoluteFixup: {
      CHECK(!xref->var || !xref->var->is_thread_local)
          << "Cannot do absolute fixup from " << std::hex << xref->ea
          << " to thread-local variable at " << std::hex << xref->target_ea
          << std::dec;

      // `target_addr` already has the right value.
      break;
    }

    case NativeXref::kThreadLocalOffsetFixup: {
      CHECK(xref->var != nullptr)
          << "Non-variable thread-local cross-reference from " << std::hex
          << xref->ea << " to " << xref->target_ea << std::dec;

      CHECK(xref->var->is_thread_local)
          << "Cannot do thread-local fixup from " << std::hex << xref->ea
          << " to non-thread-local variable at " << std::hex << xref->target_ea
          << std::dec;

      static llvm::Value *thread_base = nullptr;
      if (!thread_base) {
        thread_base = GetTLSBaseAddress(ir);
      }
      target_addr = ir.CreateSub(target_addr, thread_base);
      break;
    }
  }

  auto addr_of_xref = LiftXrefInData(xref->segment, xref->ea, false);
  ir.CreateStore(target_addr, addr_of_xref);
}

// Fill in the contents of the data segment.
static llvm::Constant *FillDataSegment(const NativeModule *cfg_module,
                                       const NativeSegment *cfg_seg,
                                       llvm::StructType *seg_type) {
  if (IsZero(cfg_seg)) {
    return llvm::ConstantAggregateZero::get(seg_type);
  }


  std::vector<llvm::Constant *> entry_vals;

  // We might add some padding on the beginning of this
  unsigned i = 0;
  if (cfg_seg->padding) {
    auto byte_type = llvm::Type::getInt8Ty(*gContext);
    auto arr_type = llvm::ArrayType::get(byte_type, cfg_seg->padding);
    entry_vals.push_back(llvm::ConstantAggregateZero::get(arr_type));
    ++i;
  }

  for (auto &cfg_seg_entry : cfg_seg->entries) {
    auto &entry = cfg_seg_entry.second;
    auto entry_type = seg_type->getContainedType(i++);

    // This entry is an opaque sequence of bytes.
    if (entry.blob) {
      if (entry.blob->is_zero) {
        entry_vals.push_back(llvm::ConstantAggregateZero::get(entry_type));

      } else if (auto bytes =
                     cfg_module->FindBytes(entry.blob->ea, entry.blob->size);
                 bytes && bytes.Size() == entry.blob->size) {

        const llvm::StringRef str_data(bytes.ToString().data(), bytes.Size());
        auto data = llvm::ConstantDataArray::getString(*gContext, str_data,
                                                       false /* AddNull */);

        CHECK(data->getType() == entry_type)
            << "Type mismatch: Got "
            << remill::LLVMThingToString(data->getType()) << " but expected "
            << remill::LLVMThingToString(entry_type);

        entry_vals.push_back(data);

      } else {
        LOG(ERROR) << "Could not find data backing " << std::hex
                   << entry.blob->ea << std::dec << " in segment "
                   << cfg_seg->name;
        entry_vals.push_back(llvm::ConstantAggregateZero::get(entry_type));
      }

    // This entry is a cross-reference.
    } else if (entry.xref) {

      auto &xref = entry.xref;
      llvm::Constant *val = nullptr;

      CHECK((entry.xref->width * 8) <= gArch->address_size)
          << "Cross-reference at " << std::hex << xref->ea << " to " << std::hex
          << xref->target_ea << " is too wide at " << entry.xref->width
          << " bytes";

      auto be_lazy = false;

      // Pointer to a (possibly external) function.
      if (xref->func) {
        const auto cfg_func = xref->func->Get();
        val = cfg_func->Pointer();

      // Pointer to a global (possibly external) variable.
      } else if (xref->var) {
        const auto cfg_var = xref->var->Get();
        val = cfg_var->Pointer();
        be_lazy = cfg_var->is_external || cfg_var->is_thread_local;

      // Pointer to an unnamed location inside of a data segment.
      } else if (xref->target_segment) {
        const auto target_seg = xref->target_segment;
        val = LiftXrefInData(target_seg, xref->target_ea, false);
        be_lazy = target_seg->is_external || target_seg->is_thread_local;

      } else {
        val = llvm::ConstantInt::get(gWordType, xref->target_ea);
        if (entry_type->isPointerTy()) {
          val = llvm::ConstantExpr::getIntToPtr(val, entry_type);
        } else {
          val = llvm::ConstantExpr::getIntToPtr(
              val, llvm::Type::getInt8PtrTy(*gContext));
        }
      }

      auto val_type = llvm::dyn_cast<llvm::PointerType>(val->getType());
      CHECK_NOTNULL(val_type);

      if (val_type->getAddressSpace()) {
        val_type = llvm::PointerType::get(val_type->getElementType(), 0);
        val = llvm::ConstantExpr::getAddrSpaceCast(val, val_type);
      }

      if (entry_type->isIntegerTy()) {
        val = llvm::ConstantExpr::getPtrToInt(val, gWordType);
        if ((gArch->address_size / 8) > xref->width) {
          val = llvm::ConstantExpr::getTrunc(val, entry_type);
          be_lazy = true;
        }

      } else if (val_type != entry_type) {
        CHECK(entry_type->isPointerTy());
        val = llvm::ConstantExpr::getBitCast(val, entry_type);
      }

      if (be_lazy && !FLAGS_force_embed_data_refs) {
        LazyInitXRef(xref.get(), val);
        val = llvm::Constant::getNullValue(entry_type);
      }

      CHECK_EQ(val->getType(), entry_type)
          << "Type mismatch: Got " << remill::LLVMThingToString(val->getType())
          << " but expected " << remill::LLVMThingToString(entry_type);

      entry_vals.push_back(val);

    } else {
      LOG(FATAL) << "Empty entry at " << std::hex << entry.ea << " in segment "
                 << cfg_seg->name;
    }
  }

  return llvm::ConstantStruct::get(seg_type, entry_vals);
}

// Fill all the data segments in a given region.
static void FillSegment(const NativeModule *cfg_module,
                        const NativeSegment *cfg_seg) {
  if (cfg_seg->entries.empty()) {
    CHECK(cfg_seg->is_external && !cfg_seg->is_exported);
    return;
  }

  auto seg = llvm::dyn_cast<llvm::GlobalVariable>(cfg_seg->Pointer());
  CHECK_NOTNULL(seg);
  if (seg->hasInitializer()) {
    return;  // Already initialized, e.g. due to `->Get()`.
  }

  auto seg_type = llvm::dyn_cast<llvm::StructType>(remill::GetValueType(seg));

  // This might be null if there are two lifted variables with same name and
  // one of them is exported and the exported variable is having xrefs or
  // notnull.
  CHECK_NOTNULL(seg_type);
  seg->setInitializer(FillDataSegment(cfg_module, cfg_seg, seg_type));
}

}  // namespace


llvm::Constant *NativeVariable::Pointer(void) const {
  CHECK(!is_external);
  CHECK_NOTNULL(segment);
  const auto cfg_seg = segment->Get();
  CHECK(!cfg_seg->is_external);

  const auto &alias_name = is_exported && !name.empty() ? name : lifted_name;
  auto alias = gModule->getNamedAlias(alias_name);
  if (alias) {
    return alias;
  }

  auto ret = LiftXrefInData(segment, ea, false /* cast_to_int */);
  if (!FLAGS_disable_aliases && is_exported) {
    auto ptr_type = llvm::dyn_cast<llvm::PointerType>(ret->getType());
    auto alias = llvm::GlobalAlias::create(
        ptr_type->getElementType(), ptr_type->getAddressSpace(),
        llvm::GlobalValue::ExternalLinkage, alias_name, ret, gModule.get());
    ret = alias;

    module->AddNameToAddress(alias_name, ea);

    if (cfg_seg->is_thread_local) {
      alias->setThreadLocalMode(llvm::GlobalValue::InitialExecTLSModel);
    }
  }
  return ret;
}

llvm::Constant *NativeVariable::Address(void) const {
  return llvm::ConstantExpr::getPtrToInt(Pointer(), gWordType);
}

llvm::Constant *NativeSegment::Address(void) const {
  auto ret = llvm::ConstantExpr::getPtrToInt(Pointer(), gWordType);
  if (padding) {
    ret = llvm::ConstantExpr::getAdd(
        ret, llvm::ConstantInt::get(gWordType, padding));
  }
  return ret;
}

llvm::Constant *NativeSegment::Pointer(void) const {
  const auto &var_name = (is_exported || is_external) ? name : lifted_name;

  auto lifted_var =
      gModule->getGlobalVariable(var_name, true /* AllowInternal */);

  if (lifted_var) {
    return lifted_var;
  }

  module->AddNameToAddress(var_name, ea);

  if (is_external) {
    LOG(INFO) << "Adding external segment " << name << " at " << std::hex << ea
              << std::dec;

    llvm::Type *var_type = nullptr;

    CHECK_NE(0, size) << "The size of the external variable '" << name
                      << "' at " << std::hex << ea << std::dec
                      << " cannot be zero";

    // Handle external variables of up to 128 bits as intgers
    // Anything else is treated as an array of bytes
    switch (size) {
      case 0:

        // Why is this zero length? This should never happen
        // Attempt a fix and output a warning
        LOG(ERROR) << "The variable '" << name << "' at " << std::hex << ea
                   << std::dec
                   << " has size of zero; Assuming it should be size 1";
        var_type = llvm::Type::getInt8Ty(*gContext);
        break;
      case 1:  // 8 bit integer
      case 2:  // 16 bit integer
      case 4:  // 32 bit integer
      case 8:  // 64 bit integer
      case 16:  // 128 bit integer
        var_type =
            llvm::Type::getIntNTy(*gContext, static_cast<unsigned>(size * 8u));
        break;

      // An array of bytes
      default: {
        auto byte_type = llvm::Type::getInt8Ty(*gContext);
        var_type = llvm::ArrayType::get(byte_type, static_cast<unsigned>(size));
        break;
      }
    }

    lifted_var = new llvm::GlobalVariable(
        *gModule, var_type, false, llvm::GlobalValue::ExternalLinkage, nullptr,
        var_name, nullptr, ThreadLocalMode(this));

  } else {
    const auto linkage = is_exported ? llvm::GlobalValue::ExternalLinkage
                                     : llvm::GlobalValue::InternalLinkage;
    LOG(INFO) << "Adding internal segment " << name;

    lifted_var = new llvm::GlobalVariable(
        *gModule, GetSegmentType(this), is_read_only, linkage, nullptr,
        var_name, nullptr, ThreadLocalMode(this));
  }

  if (ea) {
    if (const auto alignment = 1u << __builtin_ctzl(ea - padding); alignment) {
#if LLVM_VERSION_NUMBER >= LLVM_VERSION(10, 0)
      lifted_var->setAlignment(llvm::MaybeAlign(alignment));
#else
      lifted_var->setAlignment(alignment);
#endif
    }
  }

  if (!is_external && FLAGS_name_lifted_sections && !FLAGS_merge_segments) {
    std::stringstream ss;
    ss << ".section_" << std::hex << ea;
    lifted_var->setSection(ss.str());
  }

  return lifted_var;
}

llvm::Function *GetOrCreateMcSemaInitializer(void) {
  static llvm::Function *gInitFunc = nullptr;
  if (gInitFunc) {
    return gInitFunc;
  }

  LOG(INFO)
      << "Creating __mcsema_early_init function to pre-initialize runtime.";

  gInitFunc = llvm::Function::Create(
      llvm::FunctionType::get(llvm::Type::getVoidTy(*gContext), false),
      llvm::GlobalValue::InternalLinkage, "__mcsema_early_init", gModule.get());

  auto bool_type = llvm::Type::getInt1Ty(*gContext);
  auto check_var = new llvm::GlobalVariable(
      *gModule, bool_type, false, llvm::GlobalValue::InternalLinkage,
      llvm::Constant::getNullValue(bool_type));

  auto entry = llvm::BasicBlock::Create(*gContext, "", gInitFunc);
  auto already_done = llvm::BasicBlock::Create(*gContext, "", gInitFunc);
  auto lazy_xref = llvm::BasicBlock::Create(*gContext, "", gInitFunc);

  llvm::IRBuilder<> ir(entry);

  auto guard = ir.CreateLoad(check_var, true);
  ir.CreateCondBr(guard, already_done, lazy_xref);

  ir.SetInsertPoint(already_done);
  ir.CreateRetVoid();

  // Last basic block will have lazy xrefs injected into it.
  ir.SetInsertPoint(lazy_xref);
  ir.CreateStore(llvm::ConstantInt::get(bool_type, 1), check_var, true);
  ir.CreateRetVoid();

  return gInitFunc;
}

void DefineDataSegments(const NativeModule *cfg_module) {
  for (const auto &cfg_seg : cfg_module->segments) {
    FillSegment(cfg_module, cfg_seg.get());
  }
}

// Try to deduce what constructor and destructor functions should be used
bool DetectAndSetInitFiniCode(const NativeModule *cfg_module) {

  // init_fini_pairs.size % 2 == 0 must hold
  // constructor is first
  std::vector<std::pair<std::string, bool>> init_fini_pairs = {

      // Stripped binaries
      {"init", false},
      {"fini", false},

      // Not stripped binaries
      {"__libc_csu_init", false},
      {"__libc_csu_fini", false},
  };

  for (const auto &cfg_func : cfg_module->ea_to_func) {
    for (auto &init_fini_func : init_fini_pairs) {
      if (cfg_func.second->name == init_fini_func.first) {
        init_fini_func.second = true;
      }
    }
  }

  for (auto i = 0U; i < init_fini_pairs.size(); i += 2) {
    if (init_fini_pairs[i].second && init_fini_pairs[i + 1].second) {
      FLAGS_libc_constructor = init_fini_pairs[i].first;
      FLAGS_libc_destructor = init_fini_pairs[i + 1].first;
      LOG(INFO) << "Deduced libc ctor/dtor to " << FLAGS_libc_constructor
                << " / " << FLAGS_libc_destructor;
      return true;
    }
  }
  return false;
}

// Generate code to call pre-`main` function static object constructors, and
// post-`main` functions destructors.
void CallInitFiniCode(const NativeModule *cfg_module) {
  if (FLAGS_libc_constructor.empty() && FLAGS_libc_destructor.empty()) {
    if (!DetectAndSetInitFiniCode(cfg_module)) {
      return;
    }
  }

  for (const auto &entry : cfg_module->ea_to_func) {
    const auto &cfg_func = entry.second;
    llvm::Function *callback = nullptr;
    llvm::Instruction *insert_point = nullptr;

    if (FLAGS_libc_constructor.size() &&
        FLAGS_libc_constructor == cfg_func->name) {
      callback = llvm::dyn_cast<llvm::Function>(cfg_func->Pointer());
      auto init_func = GetOrCreateMcSemaConstructor();
      insert_point = &(init_func->front().back());

    } else if (FLAGS_libc_destructor.size() &&
               FLAGS_libc_destructor == cfg_func->name) {
      callback = llvm::dyn_cast<llvm::Function>(cfg_func->Pointer());
      auto fini_func = GetOrCreateMcSemaDestructor();
      insert_point = &(fini_func->front().front());
    }

    if (insert_point && callback) {
      llvm::IRBuilder<> ir(insert_point);
      ir.CreateCall(callback);
    }
  }
}

// Merge all segments into one contiguous mega segment.
void MergeSegments(const NativeModule *cfg_module) {
  if (!FLAGS_merge_segments) {
    return;
  }

  using SegPair = std::pair<const NativeSegment *, llvm::GlobalVariable *>;
  std::vector<SegPair> segs;

  for (auto [ea, seg] : cfg_module->ea_to_seg) {
    seg = seg->Get();
    if (auto var = llvm::dyn_cast<llvm::GlobalVariable>(seg->Pointer());
        var && var->hasInitializer() && !seg->is_thread_local) {
      segs.emplace_back(seg, var);
      (void) ea;
    }
  }


  std::sort(segs.begin(), segs.end(),
            [](SegPair a, SegPair b) { return a.first->ea < b.first->ea; });

  if (segs.empty()) {
    return;
  }

  const auto &dl = gModule->getDataLayout();
  llvm::Type *const u8 = llvm::Type::getInt8Ty(*gContext);
  llvm::Type *const u32 = llvm::Type::getInt32Ty(*gContext);

  auto start_ea = segs.front().first->ea & ~4095ull;
  const auto min_ea = start_ea;

  std::vector<llvm::Type *> new_types;
  std::vector<llvm::Constant *> new_vals;
  std::unordered_map<llvm::GlobalVariable *, unsigned> indices;

  const NativeSegment *prev_cfg_seg = nullptr;
  for (auto [cfg_seg, seg_var] : segs) {
    if (cfg_seg == prev_cfg_seg) {
      continue;
    }

    LOG(INFO) << "Merging segment " << cfg_seg->name << " at " << std::hex
              << cfg_seg->ea << " of size " << std::dec << cfg_seg->size;

    const auto ea = cfg_seg->ea;
    if (start_ea < ea) {
      const auto pad_type = llvm::ArrayType::get(u8, ea - start_ea);
      new_types.push_back(pad_type);
      new_vals.push_back(llvm::ConstantAggregateZero::get(pad_type));
      start_ea = ea;

    } else if (start_ea > ea) {
      LOG(FATAL) << "Segment " << cfg_seg->name << " starting at " << std::hex
                 << ea << " overlaps with previous segment "
                 << prev_cfg_seg->name << " starting at " << prev_cfg_seg->ea
                 << " and ending at " << start_ea << std::dec;
    }

    const auto init = seg_var->getInitializer();
    const auto type = init->getType();
    indices.emplace(seg_var, static_cast<unsigned>(new_types.size()));
    new_vals.push_back(init);
    new_types.push_back(type);
    start_ea += dl.getTypeStoreSize(type);
    prev_cfg_seg = cfg_seg;
  }

  llvm::StructType *const new_type =
      llvm::StructType::get(*gContext, new_types, true);

  llvm::Constant *const new_val = llvm::ConstantStruct::get(new_type, new_vals);

  auto new_var = new llvm::GlobalVariable(*gModule, new_type, false,
                                          llvm::GlobalValue::InternalLinkage,
                                          new_val, "__mcsema_all_segments");

  if (FLAGS_name_lifted_sections) {
    std::stringstream ss;
    ss << ".section_" << std::hex << min_ea;
    new_var->setSection(ss.str());
  }

  const auto const_zero = llvm::Constant::getNullValue(u32);
  for (auto [var, index] : indices) {
    auto const_index = llvm::ConstantInt::get(u32, index, false);
    llvm::Constant *const_indices[] = {const_zero, const_index};
    const auto ptr = llvm::ConstantExpr::getInBoundsGetElementPtr(
        new_type, new_var, const_indices);
    var->replaceAllUsesWith(ptr);
    var->eraseFromParent();
  }
}

}  // namespace mcsema
