/*
Copyright (c) 2017, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of the organization nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <glog/logging.h>

#include <sstream>
#include <vector>

#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "remill/Arch/Arch.h"
#include "remill/BC/Util.h"

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Segment.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

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

// Declare a data segment, and return a global value pointing to that segment.
// The type of the segment is a packed structure that is a sequence of opaque
// byte arrays, interspersed with cross-references, which will be represented
// as (pointers casted to) integers.
static void DeclareDataSegment(const NativeSegment *cfg_seg) {
  std::vector<llvm::Type *> entry_types;

  auto byte_type = llvm::Type::getInt8Ty(*gContext);
  for (const auto &cfg_seg_entry : cfg_seg->entries) {
    auto entry = cfg_seg_entry.second;
    if (entry.blob) {
      auto arr_type = llvm::ArrayType::get(byte_type, entry.blob->data.size());
      entry_types.push_back(arr_type);

    } else if (entry.xref) {
      auto val_type = llvm::Type::getIntNTy(*gContext, (entry.xref->width * 8));
      entry_types.push_back(val_type);

    } else {
      LOG(FATAL)
          << "Missing blob or xref segment entry value for segment "
          << cfg_seg->name << " data at " << std::hex << entry.ea;
    }
  }

  auto seg_type = llvm::StructType::create(entry_types, "", true);
  CHECK(nullptr != seg_type)
      << "Unable to create structure type for segment " << cfg_seg->name
      << " beginning at " << std::hex << cfg_seg->ea;

  llvm::DataLayout data_layout(gModule);
  auto seg_size = data_layout.getTypeAllocSize(seg_type);
  CHECK(seg_size == cfg_seg->size)
      << "Size of structure type of segment " << cfg_seg->name
      << " is " << seg_size << " but was expected to be " << cfg_seg->size;

  auto global = new llvm::GlobalVariable(
      *gModule, seg_type, cfg_seg->is_read_only,
      llvm::GlobalValue::InternalLinkage, nullptr,
      cfg_seg->lifted_name);
  global->setAlignment(16);
}

// Declare named variables that point into the data segment. The program being
// lifted may have cross-references that addresses meaningfully named (global)
// variables within a segment, so we want to try to preserve those names,
// treating them as GEPs into the segment's data.
void DeclareVariables(const NativeModule *cfg_module) {

  // TODO(pag): Handle thread-local storage types by assigning a non-zero
  //            address space to the byte pointer type?
  auto intptr_type = llvm::Type::getIntNTy(*gContext, gArch->address_size);
  auto byte_type = llvm::Type::getInt8Ty(*gContext);
  auto byte_ptr_type = llvm::PointerType::get(byte_type, 0);

  for (auto entry : cfg_module->ea_to_var) {
    auto cfg_var = entry.second;
    if (cfg_var && cfg_var->is_external) {
      continue;
    }

    CHECK(cfg_var && cfg_var->segment && !cfg_var->name.empty())
        << "Invalid variable at " << std::hex << entry.first;

    auto cfg_seg = cfg_var->segment;
    CHECK(cfg_var->ea >= cfg_seg->ea)
        << "Variable " << cfg_var->name << " at " << std::hex << cfg_var->ea
        << " is incorrectly assigned to the segment " << cfg_seg->name;

    auto seg = gModule->getNamedGlobal(cfg_seg->lifted_name);
    auto offset = cfg_var->ea - cfg_seg->ea;
    auto disp = llvm::ConstantInt::get(intptr_type, offset, false);

    auto seg_base = llvm::ConstantExpr::getPtrToInt(seg, intptr_type);
    auto addr = llvm::ConstantExpr::getAdd(seg_base, disp);
    auto ptr = llvm::ConstantExpr::getIntToPtr(addr, byte_ptr_type);

    (void) new llvm::GlobalVariable(
        *gModule, byte_ptr_type, true  /* IsConstant */,
        llvm::GlobalVariable::InternalLinkage,
        ptr, cfg_var->lifted_name);
  }
}

// Fill in the contents of the data segment.
static void FillDataSegment(const NativeSegment *cfg_seg) {
  auto seg = gModule->getNamedGlobal(cfg_seg->lifted_name);
  auto seg_type = llvm::dyn_cast<llvm::StructType>(seg->getValueType());

  seg->setLinkage(llvm::GlobalValue::InternalLinkage);
  seg->setVisibility(llvm::GlobalValue::DefaultVisibility);

  if (IsZero(cfg_seg)) {
    seg->setInitializer(llvm::ConstantAggregateZero::get(seg_type));
    return;
  }

  auto intptr_type = llvm::Type::getIntNTy(*gContext, gArch->address_size);
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

      auto val_size = entry.xref->width * 8;
      auto val_type = llvm::Type::getIntNTy(*gContext, val_size);
      auto xref = entry.xref;
      llvm::Constant *val = nullptr;

      CHECK(val_type == entry_type)
          << entry.xref->width << "-byte cross-reference at " << std::hex
          << xref->ea << " to " << std::hex << xref->target_ea
          << " doesn't match the type of the segment entry "
          << remill::LLVMThingToString(entry_type);

      // Pointer to a (possibly external) function.
      if (auto cfg_func = xref->func) {
        val = gModule->getFunction(cfg_func->lifted_name);
        val = llvm::ConstantExpr::getPtrToInt(val, intptr_type);
        CHECK(val != nullptr)
            << "Can't insert cross reference to function "
            << cfg_func->name << " at " << std::hex << cfg_seg_entry.first
            << " in segment " << cfg_seg->name;

      // Pointer to a global (possibly external) variable.
      } else if (auto cfg_var = xref->var) {
        val = gModule->getNamedGlobal(cfg_var->lifted_name);
        val = llvm::ConstantExpr::getPtrToInt(val, intptr_type);
        CHECK(val != nullptr)
            << "Can't insert cross reference to variable "
            << cfg_var->name << " at " << std::hex << cfg_seg_entry.first
            << " in segment " << cfg_seg->name;

      // Pointer to an unnamed location inside of a data segment.
      } else {
        auto seg = gModule->getNamedGlobal(xref->target_segment->lifted_name);
        auto offset = xref->target_ea - cfg_seg->ea;
        auto disp = llvm::ConstantInt::get(intptr_type, offset, false);
        auto seg_base = llvm::ConstantExpr::getPtrToInt(seg, intptr_type);
        val = llvm::ConstantExpr::getAdd(seg_base, disp);
      }

      // Scale and add the value in. We need to fit it to its original width.
      if (val_size > gArch->address_size) {
        val = llvm::ConstantExpr::getZExt(val, val_type);
      } else if (val_size < gArch->address_size) {
        val = llvm::ConstantExpr::getTrunc(val, val_type);
      }

      if (val->getType() != entry_type) {
        val->dump();
      }

      CHECK(val->getType() == entry_type)
          << "Type mismatch: Got "
          << remill::LLVMThingToString(val->getType())
          << " but expected "
          << remill::LLVMThingToString(entry_type);

      entry_vals.push_back(val);
    }
  }

  seg->setInitializer(llvm::ConstantStruct::get(seg_type, entry_vals));
}

}  // namespace

void AddDataSegments(const NativeModule *cfg_module) {
  for (auto cfg_segment_entry : cfg_module->segments) {
    DeclareDataSegment(cfg_segment_entry.second);
  }

  DeclareVariables(cfg_module);

  for (auto cfg_segment_entry : cfg_module->segments) {
    FillDataSegment(cfg_segment_entry.second);
  }
}

}  // namespace mcsema
