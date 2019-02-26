/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <algorithm>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/Compat/GlobalValue.h>
#include <remill/BC/Util.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/ABI.h"
#include "mcsema/BC/Callback.h"
#include "mcsema/BC/Segment.h"
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

namespace mcsema {
namespace {

// Returns `true` if all the bytes in `data` are zero.
static bool IsZero(const std::string &data) {
  for (auto b : data) {
    if (b) {
      return false;
    }
  }
  return true;
}

// Lets us decide if we can use a constant aggregate zero value, i.e.
// direct LLVM to put this data into the `.bss` segment.
static bool IsZero(const NativeSegment *cfg_seg) {
  for (const auto &cfg_seg_entry : cfg_seg->entries) {
    auto entry = cfg_seg_entry.second;
    if (entry.blob) {
      if (!IsZero(entry.blob->data)) {
        return false;
      }
    } else {
      return false;
    }
  }
  return true;
}

// The type of the segment is a packed structure that is a sequence of opaque
// byte arrays, interspersed with cross-references, which will be represented
// as (pointers casted to) integers.
static llvm::StructType *GetSegmentType(const NativeSegment *cfg_seg) {
  std::vector<llvm::Type *> entry_types;

  auto byte_type = llvm::Type::getInt8Ty(*gContext);
  for (const auto &cfg_seg_entry : cfg_seg->entries) {
    auto entry = cfg_seg_entry.second;
    if (entry.blob) {
      auto arr_type = llvm::ArrayType::get(byte_type, entry.blob->data.size());
      entry_types.push_back(arr_type);

    } else if (entry.xref) {
      auto val_type = llvm::Type::getIntNTy(
          *gContext, static_cast<unsigned>(entry.xref->width * 8));
      entry_types.push_back(val_type);

    } else {
      LOG(FATAL)
          << "Missing blob or xref segment entry value for segment "
          << cfg_seg->name << " data at " << std::hex << entry.ea;
    }
  }

  std::stringstream ss;
  ss << cfg_seg->lifted_name << "_type";

  auto seg_type = llvm::StructType::create(entry_types, ss.str(), true);
  CHECK(nullptr != seg_type)
      << "Unable to create structure type for segment " << cfg_seg->name
      << " beginning at " << std::hex << cfg_seg->ea;

  llvm::DataLayout data_layout(gModule);
  auto seg_size = data_layout.getTypeAllocSize(seg_type);
  CHECK(seg_size == cfg_seg->size)
      << "Size of structure type of segment " << cfg_seg->name
      << " is " << seg_size << " but was expected to be " << cfg_seg->size;

  return seg_type;
}

static llvm::GlobalValue::ThreadLocalMode ThreadLocalMode(
    const NativeObject *cfg_obj) {
  if (cfg_obj->is_thread_local) {
    return llvm::GlobalValue::GeneralDynamicTLSModel;
  } else {
    return llvm::GlobalValue::NotThreadLocal;
  }
}

static llvm::GlobalVariable *GlobalVariable(
    const NativeSegment *cfg_seg, std::string lifted_name) {
  auto seg_type = GetSegmentType(cfg_seg);

  auto seg_var = new llvm::GlobalVariable(
      *gModule, seg_type, cfg_seg->is_read_only,
      llvm::GlobalValue::InternalLinkage, nullptr,
      lifted_name, nullptr, ThreadLocalMode(cfg_seg));

  if (cfg_seg->is_exported) {
    seg_var->setLinkage(llvm::GlobalValue::ExternalLinkage);
  }

  return seg_var;
}

// Declare a data segment, and return a global value pointing to that segment.
static void DeclareSegment(const NativeSegment *cfg_seg) {
  cfg_seg->seg_var = gModule->getGlobalVariable(cfg_seg->lifted_name);

  if (cfg_seg->seg_var) {
    // If the variable is exported and zero initialized (not having xrefs),
    // No need to initialize these variables
    if (cfg_seg->is_exported && cfg_seg->seg_var->hasExternalLinkage()) {
      cfg_seg->needs_initializer = !IsZero(cfg_seg);
    } else {
      // If there is a variable with the same name, rename the variable
      // and set the needs_initializer flag;
      std::stringstream ss;
      ss << "internal_" << cfg_seg->lifted_name;
      cfg_seg->seg_var = GlobalVariable(cfg_seg, ss.str());

      LOG(ERROR)
          << "Segment variable '" << cfg_seg->lifted_name
          << "' was already defined";

      cfg_seg->needs_initializer = true;
    }
  } else {
    cfg_seg->seg_var = GlobalVariable(cfg_seg, cfg_seg->lifted_name);
  }
}

// Declare named variables that point into the data segment. The program being
// lifted may have cross-references that addresses meaningfully named (global)
// variables within a segment, so we want to try to preserve those names,
// treating them as GEPs into the segment's data.
static void DeclareVariables(const NativeModule *cfg_module) {
  for (auto entry : cfg_module->ea_to_var) {
    auto cfg_var = reinterpret_cast<const NativeVariable *>(
        entry.second->Get());

    if (cfg_var && cfg_var->is_external) {
      continue;
    }

    CHECK(cfg_var && cfg_var->segment && !cfg_var->name.empty())
        << "Invalid variable at " << std::hex << entry.first;

    auto cfg_seg = cfg_var->segment;
    CHECK(cfg_var->ea >= cfg_seg->ea)
        << "Variable " << cfg_var->name << " at " << std::hex << cfg_var->ea
        << " is incorrectly assigned to the segment " << cfg_seg->name;

    cfg_var->address = LiftEA(cfg_seg, cfg_var->ea);
  }
}

// Create a McSema-specific constructor/destructor function, and add it to the
// corresponding LLVM-specific array.
static llvm::Function *CreateMcSemaInitFiniImpl(
    const char *func_name, const char *arr_name) {
  LOG(INFO)
      << "Creating " << func_name << " function to initialize runtime.";

  auto func = llvm::Function::Create(
      llvm::FunctionType::get(llvm::Type::getVoidTy(*gContext), false),
      llvm::GlobalValue::InternalLinkage,
      func_name, gModule);

  auto bool_type = llvm::Type::getInt1Ty(*gContext);
  auto check_var = new llvm::GlobalVariable(
      bool_type, false, llvm::GlobalValue::InternalLinkage);
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
    LOG(INFO)
        << "Module already has a " << arr_name << " array.";

    auto arr = llvm::dyn_cast<llvm::ConstantArray>(
        global_ctors->getInitializer());
    auto num_ops = arr->getNumOperands();
    for (auto i = 0U; i < num_ops; ++i) {
      new_elems.push_back(arr->getOperand(i));
    }
  }

  new_elems.push_back(el_init);

  auto arr_type = llvm::ArrayType::get(el_type, new_elems.size());
  auto arr_init = llvm::ConstantArray::get(arr_type, new_elems);
  auto arr = new llvm::GlobalVariable(
      *gModule, arr_type, true /* isConstant */,
      llvm::GlobalVariable::AppendingLinkage,
      arr_init, global_ctors ? "__mcsema.temp_array" : arr_name);

  if (global_ctors) {
    arr->takeName(global_ctors);
    global_ctors->dropAllReferences();
    global_ctors->eraseFromParent();
  }

  return func;
}

static llvm::Function *GetOrCreateMcSemaConstructor(void) {
  static llvm::Function *gInitFunc = nullptr;
  if (!gInitFunc) {
    gInitFunc = CreateMcSemaInitFiniImpl(
        "__mcsema_constructor", "llvm.global_ctors");

    // Make sure that the `__mcsema_constructor` calls the xref initializer
    // as it's first thing.
    llvm::IRBuilder<> ir(&(gInitFunc->front().front()));
    ir.CreateCall(GetOrCreateMcSemaInitializer());
  }
  return gInitFunc;
}

static llvm::Function *GetOrCreateMcSemaDestructor(void) {
  static llvm::Function *gFiniFunc = nullptr;
  if (!gFiniFunc) {
    gFiniFunc = CreateMcSemaInitFiniImpl(
        "__mcsema_destructor", "llvm.global_dtors");
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
static void LazyInitXRef(const NativeXref *xref, llvm::Type *extern_addr_type,
                         llvm::Constant *target_addr_const) {
  auto init_func = GetOrCreateMcSemaInitializer();
  llvm::BasicBlock *block = &init_func->back();
  llvm::IRBuilder<> ir(block);
  ir.SetInsertPoint(&block->front());

  auto seg = xref->segment->seg_var;
  if (seg->isConstant()) {
    LOG(ERROR)
        << "Marking " << seg->getName().str() << " as non-constant to "
        << "support lazy initialization of reference to " << xref->target_name
        << " from " << std::hex << xref->ea;
    seg->setConstant(false);
  }

  if (!target_addr_const || target_addr_const->isNullValue()) {
    LOG_IF(FATAL, !xref->var)
        << "Cannot perform lazy relocation of non-variable cross-reference "
        << "from " << std::hex << xref->ea << " to " << xref->target_ea
        << std::dec << " (" << xref->target_name << ")";
    target_addr_const = xref->var->address;
  }

  llvm::Value *target_addr = target_addr_const;

  switch (xref->fixup_kind) {
    case NativeXref::kAbsoluteFixup: {
      CHECK(!xref->var || !xref->var->is_thread_local)
          << "Cannot do absolute fixup from " << std::hex << xref->ea
          << " to thread-local variable " << xref->target_name << " at "
          << std::hex << xref->target_ea;
      // `target_addr` already has the right value.
      break;
    }

    case NativeXref::kThreadLocalOffsetFixup: {
      CHECK(xref->var != nullptr)
          << "Non-variable thread-local cross-reference from "
          << std::hex << xref->ea << " to " << xref->target_ea << std::dec
          << " (" << xref->target_name << ")";

      CHECK(xref->var->is_thread_local)
          << "Cannot do thread-local fixup from " << std::hex << xref->ea
          << " to non-thread-local variable " << xref->target_name << " at "
          << std::hex << xref->target_ea;

      static llvm::Value *thread_base = nullptr;
      if (!thread_base) {
        thread_base = GetTLSBaseAddress(ir);
      }
      target_addr = ir.CreateSub(target_addr, thread_base);
      break;
    }
  }

  if (xref->width < gArch->address_size) {
    target_addr = ir.CreateTrunc(target_addr, extern_addr_type);
  }

  auto addr_of_xref = LiftEA(xref->segment, xref->ea);
  auto ptr_to_xref = ir.CreateIntToPtr(
      addr_of_xref, llvm::PointerType::get(extern_addr_type, 0));

  ir.CreateStore(target_addr, ptr_to_xref);
}

// Fill in the contents of the data segment.
static llvm::Constant *FillDataSegment(const NativeSegment *cfg_seg,
                                       llvm::StructType *seg_type) {
  if (IsZero(cfg_seg)) {
    return llvm::ConstantAggregateZero::get(seg_type);
  }

  unsigned i = 0;

  std::vector<llvm::Constant *> entry_vals;
  for (const auto &cfg_seg_entry : cfg_seg->entries) {

    auto entry = cfg_seg_entry.second;
    auto entry_type = seg_type->getContainedType(i++);

    // This entry is an opaque sequence of bytes.
    if (entry.blob) {
      if (IsZero(entry.blob->data)) {
        entry_vals.push_back(llvm::ConstantAggregateZero::get(entry_type));

      } else {
        auto data = llvm::ConstantDataArray::getString(
            *gContext, entry.blob->data, false /* AddNull */);

        CHECK(data->getType() == entry_type)
            << "Type mismatch: Got "
            << remill::LLVMThingToString(data->getType())
            << " but expected "
            << remill::LLVMThingToString(entry_type);

        entry_vals.push_back(data);
      }

    // This entry is a cross-reference.
    } else {
      CHECK(nullptr != entry.xref)
          << "Empty entry at " << std::hex << entry.ea
          << " in segment " << cfg_seg->name;

      auto val_size = static_cast<unsigned>(entry.xref->width * 8);
      auto val_type = llvm::Type::getIntNTy(*gContext, val_size);
      auto xref = entry.xref;
      llvm::Constant *val = nullptr;

      CHECK(val_size <= gArch->address_size)
          << "Cross-reference at " << std::hex
          << xref->ea << " to " << std::hex << xref->target_ea
          << " is too wide at " << entry.xref->width << " bytes";

      CHECK(val_type == entry_type)
          << entry.xref->width << "-byte cross-reference at " << std::hex
          << xref->ea << " to " << std::hex << xref->target_ea
          << " doesn't match the type of the segment entry "
          << remill::LLVMThingToString(entry_type);

      // Pointer to a (possibly external) function.
      if (auto cfg_func = xref->func) {
        if (cfg_func->is_external) {
          val = gModule->getFunction(cfg_func->name);
        } else {
          val = GetNativeToLiftedCallback(cfg_func);
        }

        val = llvm::ConstantExpr::getPtrToInt(val, gWordType);
        CHECK(val != nullptr)
            << "Can't insert cross reference to function "
            << cfg_func->name << " at " << std::hex << cfg_seg_entry.first
            << " in segment " << cfg_seg->name;

      // Pointer to a global (possibly external) variable.
      } else if (auto cfg_var = xref->var) {
        if (cfg_var->is_external || cfg_var->is_thread_local) {
          LOG(INFO)
              << "Adding runtime initializer for cross reference to variable "
              << cfg_var->name << " at " << std::hex << cfg_seg_entry.first
              << " in segment " << cfg_seg->name;
          LazyInitXRef(xref, val_type, val);
          val = llvm::Constant::getNullValue(gWordType);
        } else {
          val = cfg_var->address;
        }

        CHECK(val != nullptr)
            << "Can't insert cross reference to variable "
            << cfg_var->name << " at " << std::hex << cfg_seg_entry.first
            << " in segment " << cfg_seg->name;

      // Pointer to an unnamed location inside of a data segment.
      } else {
        val = LiftEA(xref->target_segment, xref->target_ea);
      }

      // Scale and add the value in. We need to fit it to its original width.
      if (val_size > gArch->address_size) {
        val = llvm::ConstantExpr::getZExt(val, val_type);

      // Pointer truncation is generating the weird code for static
      // initialization of segment variables which is causing problem
      // during recompilations. Use Lazy initialization of the variable
      //    segXXXX__gcc_except_table
      // Wrongly generated static initializer looks like following:
      //    .long   _ZTI12out_of_range&-1
      //    .long   _ZTI17special_condition&-1
      } else if (val_size < gArch->address_size) {
        LazyInitXRef(xref, val_type, val);
        val = llvm::ConstantInt::getNullValue(val_type);
      }

      CHECK(val->getType() == entry_type)
          << "Type mismatch: Got "
          << remill::LLVMThingToString(val->getType())
          << " but expected "
          << remill::LLVMThingToString(entry_type);

      entry_vals.push_back(val);
    }
  }

  return llvm::ConstantStruct::get(seg_type, entry_vals);
}

// Fill all the data segments in a given region.
static void FillSegment(const NativeSegment *cfg_seg) {
  auto seg = cfg_seg->seg_var;
  if (cfg_seg->needs_initializer) {
    CHECK_NOTNULL(seg);
    auto seg_type = llvm::dyn_cast<llvm::StructType>(remill::GetValueType(seg));

    // This might be null if there are two lifted variables with same name and one of them is exported
    // and the exported variable is having xrefs or notnull.
    CHECK_NOTNULL(seg_type);
    seg->setInitializer(FillDataSegment(cfg_seg, seg_type));
  }
}

}  // namespace

llvm::Function *GetOrCreateMcSemaInitializer(void) {
  static llvm::Function *gInitFunc = nullptr;
  if (!gInitFunc) {
    LOG(INFO)
          << "Creating __mcsema_early_init function to pre-initialize runtime.";

    gInitFunc = llvm::Function::Create(
        llvm::FunctionType::get(llvm::Type::getVoidTy(*gContext), false),
        llvm::GlobalValue::InternalLinkage,
        "__mcsema_early_init", gModule);

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
  }
  return gInitFunc;
}

void DeclareDataSegments(const NativeModule *cfg_module) {
  for (auto cfg_seg_entry : cfg_module->segments) {
    DeclareSegment(cfg_seg_entry.second);
  }

  DeclareVariables(cfg_module);
}

void DefineDataSegments(const NativeModule *cfg_module) {
  for (auto cfg_seg_entry : cfg_module->segments) {
    FillSegment(cfg_seg_entry.second);
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
      if (cfg_func.second->name ==  init_fini_func.first) {
        init_fini_func.second = true;
      }
    }
  }

  for (auto i = 0U; i < init_fini_pairs.size(); i += 2) {
    if (init_fini_pairs[i].second && init_fini_pairs[i + 1].second) {
      FLAGS_libc_constructor = init_fini_pairs[i].first;
      FLAGS_libc_destructor = init_fini_pairs[i + 1].first;
      LOG(INFO) << "Deduced libc ctor/dtor to "
                << FLAGS_libc_constructor << " / "
                << FLAGS_libc_destructor;
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
    auto cfg_func = entry.second;
    llvm::Function *callback = nullptr;
    llvm::Instruction *insert_point = nullptr;

    if (FLAGS_libc_constructor.size() &&
        FLAGS_libc_constructor == cfg_func->name) {
      callback = GetNativeToLiftedCallback(cfg_func);
      auto init_func = GetOrCreateMcSemaConstructor();
      insert_point = &(init_func->front().back());

    } else if (FLAGS_libc_destructor.size() &&
               FLAGS_libc_destructor == cfg_func->name) {
      callback = GetNativeToLiftedCallback(cfg_func);
      auto fini_func = GetOrCreateMcSemaDestructor();
      insert_point = &(fini_func->front().front());
    }

    if (insert_point && callback) {
      llvm::IRBuilder<> ir(insert_point);
      ir.CreateCall(callback);
    }
  }
}

}  // namespace mcsema
