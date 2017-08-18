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

DEFINE_bool(partition_segments, false,
            "Partition segments into separate variables, even if they are "
            "contiguous in the binary. By default this is disabled and "
            "the data of contiguous segments are concatenated together into a "
            "global variable. This is the default just in case some code uses "
            "the address of the beginning of one segment to represent the "
            "logical end of a prior segment.");

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
  return false;
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

// Declare a data segment, and return a global value pointing to that segment.
static llvm::GlobalVariable *DeclareRegion(const SegmentMap &segments) {
  std::vector<llvm::Type *> seg_types;

  uint64_t min_ea = std::numeric_limits<uint64_t>::max();
  uint64_t max_ea = 0;
  auto is_read_only = true;

  for (const auto &entry : segments) {
    auto cfg_seg = entry.second;
    auto type = GetSegmentType(cfg_seg);
    seg_types.push_back(type);

    auto seg_end_ea = cfg_seg->ea + cfg_seg->size;
    min_ea = std::min(min_ea, cfg_seg->ea);
    max_ea = std::max(max_ea, seg_end_ea);
    is_read_only = is_read_only && cfg_seg->is_read_only;
  }

  // If a region contains both read-write and read-only segments, then we're
  // going to have to convert the read-only segment into read-write.
  //
  // TODO(pag): What happens if a thread-local and non-thread-local segment
  //            appear in the same region?
  for (const auto &entry : segments) {
    auto cfg_seg = entry.second;
    auto seg_end_ea = cfg_seg->ea + cfg_seg->size;
    LOG_IF(ERROR, cfg_seg->is_read_only && !is_read_only)
        << "Adding read-only segment " << cfg_seg->name << " at ["
        << std::hex << cfg_seg->ea << ", " << std::hex << seg_end_ea
        << ") into non-read-only segment region [" << std::hex << min_ea
        << ", " << std::hex << max_ea << ")";
  }

  std::stringstream ss;
  ss << "region_" << std::hex << min_ea << "_" << std::hex << max_ea;
  auto region_name = ss.str();
  ss << "_type";

  auto region_type = llvm::StructType::create(seg_types, ss.str(), true);

  CHECK(nullptr != region_type)
      << "Unable to create structure type for segment region ["
      << std::hex << min_ea << ", " << std::hex << max_ea << ")";

  // Declare the region as a large structure.
  auto region = new llvm::GlobalVariable(
      *gModule, region_type, is_read_only,
      llvm::GlobalValue::InternalLinkage, nullptr,
      region_name);
  region->setAlignment(16);

  // Go and declare the individual segments as variables, whose values are
  // addresses into the region.
  for (const auto &entry : segments) {
    auto cfg_seg = entry.second;
    auto offset = cfg_seg->ea - min_ea;

    std::vector<llvm::Constant *> index_list;
    index_list.push_back(llvm::ConstantInt::get(gWordType, offset));

    auto ptr = llvm::ConstantExpr::getAdd(
        llvm::ConstantExpr::getPtrToInt(region, gWordType),
        llvm::ConstantInt::get(gWordType, offset));

    cfg_seg->region_var = region;
    cfg_seg->seg_var = new llvm::GlobalVariable(
        *gModule, gWordType, true  /* isConstant */,
        llvm::GlobalVariable::InternalLinkage,
        ptr, cfg_seg->lifted_name);
  }
  return region;
}

// Declare named variables that point into the data segment. The program being
// lifted may have cross-references that addresses meaningfully named (global)
// variables within a segment, so we want to try to preserve those names,
// treating them as GEPs into the segment's data.
static void DeclareVariables(const NativeModule *cfg_module) {

  // TODO(pag): Handle thread-local storage types by assigning a non-zero
  //            address space to the byte pointer type?

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

    auto seg = gModule->getGlobalVariable(cfg_seg->lifted_name, true);
    CHECK(seg != nullptr)
        << "Cannot find segment variable " << cfg_seg->lifted_name
        << " for segment " << cfg_seg->name;

    auto offset = cfg_var->ea - cfg_seg->ea;
    auto ptr = llvm::ConstantExpr::getAdd(
        seg->getInitializer(),
        llvm::ConstantInt::get(gWordType, offset));

    (void) new llvm::GlobalVariable(
        *gModule, gWordType, true  /* isConstant */,
        llvm::GlobalVariable::InternalLinkage,
        ptr, cfg_var->lifted_name);
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

  llvm::IRBuilder<> ir(llvm::BasicBlock::Create(*gContext, "", func));
  ir.CreateRetVoid();

  auto i32_type = llvm::Type::getInt32Ty(*gContext);
  auto ptr_type = llvm::Type::getInt8PtrTy(*gContext);
  auto el_type = llvm::StructType::get(
      i32_type, func->getType(), ptr_type, nullptr);
  auto el_init = llvm::ConstantStruct::get(
      el_type,
      llvm::ConstantInt::get(i32_type, 101),  // Lowest non-system priority.
      func,
      llvm::Constant::getNullValue(ptr_type),
      nullptr);

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
static void LazyInitXRef(const NativeXref *xref,
                         llvm::GlobalVariable *extern_ptr_var,
                         llvm::Type *extern_addr_type) {
  auto init_func = GetOrCreateMcSemaConstructor();
  llvm::BasicBlock *block = &init_func->front();
  llvm::IRBuilder<> ir(block);
  ir.SetInsertPoint(&block->front());

  auto extern_ptr_type = llvm::PointerType::get(extern_addr_type, 0);
  auto xref_target = ir.CreateLoad(
      ir.CreateBitCast(extern_ptr_var, extern_ptr_type));

  auto seg = xref->segment->seg_var;
  auto region = xref->segment->region_var;
  if (seg->isConstant() || region->isConstant()) {
    LOG(ERROR)
        << "Marking " << region->getName().str() << " as non-constant to "
        << "support lazy initialization of reference to " << xref->target_name
        << " from " << std::hex << xref->ea;
    seg->setConstant(false);
    region->setConstant(false);
  }

  auto offset = xref->ea - xref->segment->ea;
  auto disp = llvm::ConstantInt::get(gWordType, offset, false);
  auto addr_of_xref = llvm::ConstantExpr::getAdd(seg->getInitializer(), disp);
  auto ptr_to_xref = ir.CreateIntToPtr(addr_of_xref, extern_ptr_type);
  ir.CreateStore(xref_target, ptr_to_xref);
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
        auto var = gModule->getGlobalVariable(cfg_var->lifted_name, true);
        CHECK(var != nullptr)
            << "Can't insert cross reference to variable "
            << cfg_var->name << " at " << std::hex << cfg_seg_entry.first
            << " in segment " << cfg_seg->name;

        val = var->getInitializer();
        if (!val) {

          // TODO(pag): This can come up in a few cases, and will eventually
          //            need runtime support to handle. The gist of the issue
          //            is this that we have a reference in the data section
          //            to an external global variable, but we can't splat in
          //            a value for the cross-reference because it won't
          //            be known until runtime. This is the type of thing in
          //            libc that gets handled by constructor functions.
          LOG(WARNING)
              << "Likely external data cross-reference from " << std::hex
              << xref->ea << " to " << cfg_var->name << " at " << std::hex
              << cfg_var->ea << " (lifted as " << cfg_var->lifted_name
              << ") does not have an initializer.";

          val = llvm::ConstantInt::get(val_type, 0);
          LazyInitXRef(xref, var, val_type);
        }

      // Pointer to an unnamed location inside of a data segment.
      } else {
        auto seg = gModule->getGlobalVariable(
            xref->target_segment->lifted_name, true);
        auto offset = xref->target_ea - xref->target_segment->ea;
        auto disp = llvm::ConstantInt::get(gWordType, offset, false);
        val = llvm::ConstantExpr::getAdd(seg->getInitializer(), disp);
      }

      // Scale and add the value in. We need to fit it to its original width.
      if (val_size > gArch->address_size) {
        val = llvm::ConstantExpr::getZExt(val, val_type);
      } else if (val_size < gArch->address_size) {
        val = llvm::ConstantExpr::getTrunc(val, val_type);
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
static void FillRegion(llvm::GlobalVariable *global, const SegmentMap &region) {
  std::vector<llvm::Constant *> entry_vals;
  auto region_type = llvm::dyn_cast<llvm::StructType>(
      remill::GetValueType(global));

  unsigned i = 0;
  for (const auto &entry : region) {
    auto cfg_seg = entry.second;
    entry_vals.push_back(FillDataSegment(
        cfg_seg,
        llvm::dyn_cast<llvm::StructType>(region_type->getContainedType(i++))));
  }

  global->setInitializer(llvm::ConstantStruct::get(region_type, entry_vals));
}

using Region = std::vector<SegmentMap>;

// We need to group together contiguous segments. It's sometimes the
// case that code will reference the address immediately following a segment
// as a way of bounding the segment using a less-than comparison. This ending
// address can be the beginning of another segment, so we need to actually
// make sure that we maintain the correct addresses.
//
// TODO(pag): This is very conservative. Can we make it less so by checking to
//            see if there's a reference to the first byte of a segment that
//            immediately follows another one, and if there's no such reference
//            then treat them as part of different regions?
//
// TODO(pag): Read-only and read-write segments being in the same region.
//
// TODO(pag): Thread-local and global segments being in the same region.
//
// TODO(pag): Perhaps in the above cases, we can permit references to actually
//            reference just beyond the end of a segment.
static Region PartitionSegments(const NativeModule *cfg_module) {
  Region groups;
  groups.reserve(cfg_module->segments.size());

  NativeSegment *last_seg = nullptr;
  for (auto cfg_segment_entry : cfg_module->segments) {
    auto cfg_seg = cfg_segment_entry.second;
    if (!FLAGS_partition_segments &&
        last_seg && (last_seg->ea + last_seg->size) == cfg_seg->ea) {
      auto &prev_group = groups[groups.size() - 1];
      prev_group[cfg_seg->ea] = cfg_seg;
    } else {
      SegmentMap new_group;
      new_group[cfg_seg->ea] = cfg_seg;
      groups.push_back(new_group);
    }
    last_seg = cfg_seg;
  }
  return groups;
}

}  // namespace

void AddDataSegments(const NativeModule *cfg_module) {

  auto regions = PartitionSegments(cfg_module);
  std::vector<llvm::GlobalVariable *> region_vars;

  for (const auto &region : regions) {
    region_vars.push_back(DeclareRegion(region));
  }

  DeclareVariables(cfg_module);

  unsigned i = 0;
  for (const auto &region : regions) {
    FillRegion(region_vars[i++], region);
  }
}

void CallInitFiniCode(const NativeModule *cfg_module) {
  if (FLAGS_libc_constructor.empty() && FLAGS_libc_destructor.empty()) {
    return;
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
      auto fini_func = GetOrCreateMcSemaDestructor();
      insert_point = &(fini_func->front().front());
    }

    if (insert_point) {
      llvm::IRBuilder<> ir(insert_point);
      auto call = ir.CreateCall(callback);
      call->setCallingConv(llvm::CallingConv::Fast);
    }
  }
}

}  // namespace mcsema
