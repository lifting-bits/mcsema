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

#include <glog/logging.h>

#include <algorithm>
#include <vector>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "mcsema/Arch/ABI.h"
#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Util.h"

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"
#include "remill/OS/OS.h"

namespace mcsema {

enum ValueKind {
  kInvalidKind = 0,
  kI8 = (1 << 0),
  kI16 = (1 << 1),
  kI32 = (1 << 2),
  kI64 = (1 << 3),
  kF32 = (1 << 4),
  kF64 = (1 << 5),
  kF80 = (1 << 6),
  kVec = (1 << 7),

  kIntegralLeast32 = kI8 | kI16 | kI32,
  kIntegralLeast64 = kI8 | kI16 | kI32 | kI64,
};

namespace {

static ValueKind KindOfValue(llvm::Type *type) {
  if (!type || type->isPointerTy()) {
    return (32 == gArch->address_size) ? kI32 : kI64;

  } else if (type->isVectorTy()) {
    return kVec;
  } else if (type->isIntegerTy()) {
    llvm::DataLayout dl(gModule);
    switch (dl.getTypeAllocSize(type)) {
      case 8: return kI64;
      case 4: return kI32;
      case 2: return kI16;
      case 1: return kI8;
      default:
        return kInvalidKind;
    }
  } else if (type->isX86_FP80Ty()) {
    return kF80;
  } else if (type->isDoubleTy()) {
    return kF64;
  } else if (type->isFloatTy()) {
    return kF32;
  } else {
    return kInvalidKind;
  }
}

static const char *StackPointerName(void) {
  static const char *sp_name = nullptr;
  if (sp_name) {
    return sp_name;
  }

  switch (gArch->arch_name) {
    case remill::kArchAArch64LittleEndian:
      sp_name = "SP";
      break;

    case remill::kArchX86:
    case remill::kArchX86_AVX:
    case remill::kArchX86_AVX512:
      sp_name = "ESP";
      break;

    case remill::kArchAMD64:
    case remill::kArchAMD64_AVX:
    case remill::kArchAMD64_AVX512:
      sp_name = "RSP";
      break;
    default:
      LOG(FATAL)
          << "Can't get stack pointer name for architecture: "
          << remill::GetArchName(gArch->arch_name);
      return nullptr;
  }

  return sp_name;
}

static const char *ThreadPointerNameX86(void) {
  switch (gArch->os_name) {
    case remill::kOSLinux:
      return "GS_BASE";
    case remill::kOSWindows:
      return "FS_BASE";
    default:
      return nullptr;
  }
}

static const char *ThreadPointerNameAMD64(void) {
  switch (gArch->os_name) {
    case remill::kOSLinux:
      return "FS_BASE";
    case remill::kOSWindows:
      return "GS_BASE";
    default:
      return nullptr;
  }
}

static const char *ThreadPointerName(void) {
  static const char *tp_name = nullptr;
  if (tp_name) {
    return tp_name;
  }

  switch (gArch->arch_name) {
    case remill::kArchAArch64LittleEndian:
      tp_name = "TPIDR_EL0";
      break;

    case remill::kArchX86:
    case remill::kArchX86_AVX:
    case remill::kArchX86_AVX512:
      tp_name = ThreadPointerNameX86();
      break;

    case remill::kArchAMD64:
    case remill::kArchAMD64_AVX:
    case remill::kArchAMD64_AVX512:
      tp_name = ThreadPointerNameAMD64();
      break;

    default:
      break;
  }

  LOG_IF(ERROR, !tp_name)
      << "Can't get thread pointer name for architecture "
      << remill::GetArchName(gArch->arch_name) << " and OS "
      << remill::GetOSName(gArch->os_name);
  return tp_name;
}

static uint64_t GetVectorRegSize() {
  switch (gArch->arch_name) {
    case remill::kArchAMD64:
    case remill::kArchX86:
      return 16;
    case remill::kArchAMD64_AVX:
    case remill::kArchX86_AVX:
      return 32;
    case remill::kArchAMD64_AVX512:
    case remill::kArchX86_AVX512:
      return 64;
    default:
      LOG(FATAL) << "Unkown vector register size for arch other than amd64, x86";
   }
}

static const char *GetVectorRegisterBase(size_t& number) {
  switch(gArch->arch_name) {
    case remill::kArchAMD64_AVX:
      number = 16;
      return "YMM";
    case remill::kArchX86_AVX:
      number = 8;
      return "YMM";
    case remill::kArchAMD64_AVX512:
      number = 32;
      return "ZMM";
    case remill::kArchX86_AVX512:
      number = 8;
      return "ZMM";
    case remill::kArchAMD64:
      number = 8;
      return "XMM";
    default:
      LOG(FATAL) << "Trying to use vector registers "
        << "with something else than x86, amd64";
  }
}

//TODO(lukas): vector registers for other archs
static std::vector<ArgConstraint> ConstraintTable(llvm::CallingConv::ID cc) {
  const ArgConstraint kNoArgs = {"", kInvalidKind};
  if (llvm::CallingConv::X86_64_SysV == cc) {
    std::vector<ArgConstraint> kAmd64SysVArgs = {
      {"RDI", kIntegralLeast64},
      {"RSI", kIntegralLeast64},
      {"RDX", kIntegralLeast64},
      {"RCX", kIntegralLeast64},
      {"R8", kIntegralLeast64},
      {"R9", kIntegralLeast64}
    };
    size_t size = 0;
    std::string vector_base_name = GetVectorRegisterBase(size);
    for (unsigned i = 0; i < size; ++i) {
      auto name = vector_base_name + std::to_string(i);
      kAmd64SysVArgs.push_back({name, kF32 | kF64 | kVec});
    }
    kAmd64SysVArgs.push_back(kNoArgs);
    return kAmd64SysVArgs;

  } else if (llvm::CallingConv::Win64 == cc) {
    std::vector<ArgConstraint> kAmd64Win64Args = {
      {"RCX", kIntegralLeast64},
      {"RDX", kIntegralLeast64},
      {"R8", kIntegralLeast64},
      {"R9", kIntegralLeast64}
    };
    size_t size = 0;
    std::string vector_base_name = GetVectorRegisterBase(size);
    for (unsigned i = 0; i < size; ++i) {
      auto name = vector_base_name + std::to_string(i);
      kAmd64Win64Args.push_back({name, kF32 | kF64 | kVec});
    }
    kAmd64Win64Args.push_back(kNoArgs);
    return kAmd64Win64Args;

  } else if (llvm::CallingConv::X86_FastCall == cc) {
    std::vector<ArgConstraint> kX86FastCallArgs = {
        {"ECX", kIntegralLeast32},
        {"EDX", kIntegralLeast32},
        {nullptr, kInvalidKind},
    };
    return kX86FastCallArgs;

  } else if (llvm::CallingConv::X86_ThisCall == cc) {
    std::vector<ArgConstraint> kX86ThisCallArgs = {
        {"ECX", kIntegralLeast32},
        {nullptr, kInvalidKind},
    };
    return kX86ThisCallArgs;

  } else if (llvm::CallingConv::X86_StdCall == cc) {
    return std::vector<ArgConstraint> {kNoArgs};  // stdcall takes all args on the stack.

  } else if (llvm::CallingConv::C == cc) {
    if (gArch->IsX86()) {
      return {kNoArgs};  // cdecl takes all args on the stack.

    } else if (gArch->IsAArch64()) {
      std::vector<ArgConstraint> kAArch64Args = {
          {"X0", kIntegralLeast64},
          {"X1", kIntegralLeast64},
          {"X2", kIntegralLeast64},
          {"X3", kIntegralLeast64},
          {"X4", kIntegralLeast64},
          {"X5", kIntegralLeast64},
          {"X6", kIntegralLeast64},
          {"X7", kIntegralLeast64},

          {"D0", kF32 | kF64},
          {"D1", kF32 | kF64},
          {"D2", kF32 | kF64},
          {"D3", kF32 | kF64},
          {"D4", kF32 | kF64},
          {"D5", kF32 | kF64},
          {"D6", kF32 | kF64},
          {"D7", kF32 | kF64},
          {"D8", kF32 | kF64},
          {"D9", kF32 | kF64},
          {"D10", kF32 | kF64},
          {"D11", kF32 | kF64},
          {"D12", kF32 | kF64},
          {"D13", kF32 | kF64},
          {"D14", kF32 | kF64},
          {"D15", kF32 | kF64},
          {"D16", kF32 | kF64},
          {"D17", kF32 | kF64},
          {"D18", kF32 | kF64},
          {"D19", kF32 | kF64},
          {"D20", kF32 | kF64},
          {"D21", kF32 | kF64},
          {"D22", kF32 | kF64},
          {"D23", kF32 | kF64},
          {"D24", kF32 | kF64},
          {"D25", kF32 | kF64},
          {"D26", kF32 | kF64},
          {"D27", kF32 | kF64},
          {"D28", kF32 | kF64},
          {"D29", kF32 | kF64},
          {"D30", kF32 | kF64},
          {"D31", kF32 | kF64},

          {nullptr, kInvalidKind},
      };
      return kAArch64Args;
    }
  }

  LOG(FATAL)
      << "Unknown ABI/calling convention: " << cc;
  return {kNoArgs};
}

static std::vector<ArgConstraint> ReturnRegsTable(llvm::CallingConv::ID cc) {
  std::vector<ArgConstraint> table;

  if (llvm::CallingConv::X86_64_SysV == cc) {
    table.push_back({"RAX", kIntegralLeast64});
    table.push_back({"RDX", kIntegralLeast64});

  } else if (llvm::CallingConv::Win64 == cc) {
    table.push_back({"RAX", kIntegralLeast64});

  } else if (llvm::CallingConv::X86_StdCall == cc ||
             llvm::CallingConv::X86_FastCall == cc ||
             llvm::CallingConv::X86_ThisCall == cc) {
    table.push_back({"EAX", kIntegralLeast32});

  } else if (llvm::CallingConv::C == cc) {
    if (gArch->IsX86()) {
      table.push_back({"EAX", kIntegralLeast32});  // cdecl.

    } else if (gArch->IsAArch64()) {
      table.push_back({"X0", kIntegralLeast64});
    }
  }

  // note(lukas): Not sure how many vector regs can be used for return,
  // but it looks possibly all of them
  if (llvm::CallingConv::X86_64_SysV == cc) {
    size_t size = 0;
    std::string vector_base_name = GetVectorRegisterBase(size);
    for (unsigned i = 0; i < size; ++i) {
      auto name = vector_base_name + std::to_string(i);
      table.push_back({name, kF32 | kF64 | kVec});
    }
  } else if (llvm::CallingConv::Win64 == cc) {
    size_t size = 0;
    std::string vector_base_name = GetVectorRegisterBase(size);
    for (unsigned i = 0; i < size; ++i) {
      auto name = vector_base_name + std::to_string(i);
      table.push_back({name, kF32 | kF64 | kVec});
    }
  } else if (llvm::CallingConv::X86_StdCall == cc ||
             llvm::CallingConv::X86_FastCall == cc ||
             llvm::CallingConv::X86_ThisCall == cc) {
    table.push_back({"ST0", kF32 | kF64 });

  } else if (llvm::CallingConv::C == cc) {
    if (gArch->IsX86()) {
      table.push_back({"EAX", kF32});  // cdecl.

    } else if (gArch->IsAArch64()) {
      table.push_back({"D0", kF64});
      table.push_back({"S0", kF32});
    }
  }
  // TODO(lukas): Tide everything here up!
  table.push_back({"ST0", kF80 });
  table.push_back({"ST1", kF80});
  table.push_back({"", kInvalidKind});
  return table;
}

static uint64_t DefaultUsedStackBytes(llvm::CallingConv::ID cc) {
  switch (cc) {
    case llvm::CallingConv::X86_64_SysV:
      return 8;  // Size of return address on the stack.

    case llvm::CallingConv::Win64:
      return 8 + 32;  // Return address + shadow space.

    case llvm::CallingConv::X86_FastCall:
    case llvm::CallingConv::X86_StdCall:
    case llvm::CallingConv::X86_ThisCall:
      return 4;  // Size of return address on the stack.

    default:
      return 0;
  }
}

static llvm::Type* RetrieveArgumentType(llvm::Type *original_type, unsigned index) {
  if (original_type->isPointerTy()) {
    return original_type;
  }
  if (auto struct_type = llvm::dyn_cast<llvm::StructType>(original_type)) {
    return struct_type->getElementType(index);
  } else {
    return original_type;
  }
}

// llvm::CompositeType as common parent does not provide getNumElements
static uint64_t GetNumberOfElements(llvm::Type* original_type) {
  if (auto struct_type = llvm::dyn_cast<llvm::StructType>(original_type)) {
    return struct_type->getNumElements();
  } else {
    return 1;
  }
}

}  // namespace

CallingConvention::CallingConvention(llvm::CallingConv::ID cc_)
    : cc(cc_),
      used_reg_bitmap(0),
      used_return_bitmap(0),
      num_loaded_stack_bytes(DefaultUsedStackBytes(cc)),
      num_stored_stack_bytes(0),
      sp_name(StackPointerName()),
      tp_name(ThreadPointerName()),
      reg_table(ConstraintTable(cc)),
      return_table(ReturnRegsTable(cc)) {}

// Scan through the register table. If we can match this argument request
// to a register then do so.
const char *CallingConvention::GetVarImpl(
    llvm::Type *val_type,
    const std::vector<ArgConstraint> &table,
    uint64_t &bitmap) {

  auto val_kind = KindOfValue(val_type);
  for (uint64_t i = 0; ; ++i) {
    const auto &reg_loc = table[i];
    if (reg_loc.var_name.empty()) {
      break;
    }
    if (val_kind == (reg_loc.accepted_val_kinds & val_kind)) {
      auto mask = 1ULL << i;
      if (!(bitmap & mask)) {
        bitmap |= mask;
        //TODO(lukas): Return string
        return reg_loc.var_name.c_str();
      }
    }
  }
  return nullptr;
}

const char *CallingConvention::GetVarForNextArgument(llvm::Type *val_type) {
  return GetVarImpl(val_type, reg_table, used_reg_bitmap);
}

const char *CallingConvention::GetVarForNextReturn(llvm::Type *val_type) {
  return GetVarImpl(val_type, return_table, used_return_bitmap);
}

static llvm::Function *ReadIntFromMemFunc(uint64_t size_bytes) {
  if (8 == size_bytes) {
    return gModule->getFunction("__remill_read_memory_64");
  } else if (4 == size_bytes) {
    return gModule->getFunction("__remill_read_memory_32");
  } else if (2 == size_bytes) {
    return gModule->getFunction("__remill_read_memory_16");
  } else if (1 == size_bytes) {
    return gModule->getFunction("__remill_read_memory_8");
  } else {
    LOG(FATAL)
        << "Cannot find function to read " << size_bytes
        << "-byte integer from memory.";
    return nullptr;
  }
}

static llvm::Function *WriteIntToMemFunc(uint64_t size_bytes) {
  if (8 == size_bytes) {
    return gModule->getFunction("__remill_write_memory_64");
  } else if (4 == size_bytes) {
    return gModule->getFunction("__remill_write_memory_32");
  } else if (2 == size_bytes) {
    return gModule->getFunction("__remill_write_memory_16");
  } else if (1 == size_bytes) {
    return gModule->getFunction("__remill_write_memory_8");
  } else {
    LOG(FATAL)
        << "Cannot find function to read " << size_bytes
        << "-byte integer from memory.";
    return nullptr;
  }
}

llvm::Value* InsertIntoVector(llvm::BasicBlock *block,
                              llvm::Value *base_value,
                              llvm::Value *reg_ptr,
                              size_t count, size_t start=0) {

  llvm::IRBuilder<> ir(block);
  for (size_t i = 0; i < count; ++i) {
    auto offset = ir.CreateGEP(reg_ptr, GetConstantInt(64, i));
    auto load = ir.CreateLoad(offset);
    base_value = ir.CreateInsertElement(base_value, load,
        GetConstantInt(64, i + start));
  }
  return base_value;

}

llvm::Value *CallingConvention::LoadVectorArgument(
    llvm::BasicBlock *block,
    llvm::VectorType *goal_type) {

  llvm::IRBuilder<> ir(block);
  llvm::Value *base_value = llvm::Constant::getNullValue(goal_type);

  auto under_type = goal_type->getElementType();
  auto num_elements = goal_type->getNumElements();

  size_t reg_size = GetVectorRegSize();

  llvm::DataLayout dl(gModule);
  auto element_size = dl.getTypeAllocSize(under_type);
  size_t reg_element_capacity = reg_size / element_size;
  int32_t remaining = static_cast<int32_t>(num_elements);

  for ( unsigned i = 0; remaining > 0; ++i, remaining -= reg_size) {
    //auto reg_var_name = reg_base_name + std::to_string(i);
    auto reg_var_name = GetVarForNextArgument(goal_type);
    LOG(INFO) << reg_var_name;

    llvm::Value *dest_loc = remill::FindVarInFunction(block, reg_var_name);
    dest_loc = ir.CreateBitCast(dest_loc,
        llvm::PointerType::get(under_type, 0));

    auto count = std::min(reg_element_capacity, static_cast<size_t>(remaining));
    LOG(INFO) << count << " " << reg_element_capacity << " " << element_size;
    base_value = InsertIntoVector(block, base_value, dest_loc,
        count, i * reg_element_capacity);
  }
  return base_value;
}


llvm::Value *CallingConvention::LoadNextSimpleArgument(
    llvm::BasicBlock *block,
    llvm::Type *goal_type) {
  if (!goal_type) {
    goal_type = gWordType;
  }

  llvm::IRBuilder<> ir(block);

  // Vector type means there will be something packed
  // and need special handling
  if (auto vector_type = llvm::dyn_cast<llvm::VectorType>(goal_type)) {
    return LoadVectorArgument(block, vector_type);
  }

  if (auto reg_var_name = GetVarForNextArgument(goal_type)) {
    auto reg_ptr = remill::FindVarInFunction(block, reg_var_name);
    return ir.CreateLoad(
        ir.CreateBitCast(reg_ptr, llvm::PointerType::get(goal_type, 0)));
  }

  // We can't match the argument request to a register, so lets look for it on
  // the stack. The supported calling conventions are sane, to the extent
  // that they push arguments onto the stack in reverse order (i.e. last arg
  // first).
  auto sp = LoadStackPointer(block);
  CHECK(sp->getType() == gWordType);

  auto addr_size = gArch->address_size / 8U;
  auto offset = llvm::ConstantInt::get(gWordType, num_loaded_stack_bytes);

  auto addr = ir.CreateAdd(sp, offset);
  std::vector<llvm::Value *> args = {remill::LoadMemoryPointer(block), addr};

  llvm::DataLayout dl(gModule);
  auto alloc_size = dl.getTypeAllocSize(goal_type);

  llvm::Value *val = nullptr;

  if (goal_type->isX86_FP80Ty()) {
    val = ir.CreateFPExt(
        ir.CreateCall(gModule->getFunction("__remill_read_memory_f80"), args),
        llvm::Type::getX86_FP80Ty(*gContext));

  } else if (goal_type->isDoubleTy()) {
    val = ir.CreateCall(gModule->getFunction("__remill_read_memory_f64"), args);

  } else if (goal_type->isFloatTy()) {
    val = ir.CreateCall(gModule->getFunction("__remill_read_memory_f32"), args);

  } else if (goal_type->isIntegerTy()) {
    auto read_mem = ReadIntFromMemFunc(alloc_size);
    val = ir.CreateCall(read_mem, args);
    if (dl.getTypeSizeInBits(goal_type) <
        dl.getTypeAllocSizeInBits(goal_type)) {
      val = ir.CreateTrunc(val, goal_type);
    }

  } else if (goal_type->isPointerTy()) {
    llvm::Function *func = nullptr;
    if (32 == gArch->address_size) {
      func = gModule->getFunction("__remill_read_memory_32");
    } else {
      func = gModule->getFunction("__remill_read_memory_64");
    }
    val = ir.CreateIntToPtr(ir.CreateCall(func, args), goal_type);

  } else {
    LOG(FATAL)
        << "Can't handle reading an " << remill::LLVMThingToString(goal_type)
        << " value from the stack";
  }

  // Bump the stack pointer.
  alloc_size = std::max<uint64_t>(alloc_size, addr_size);
  num_loaded_stack_bytes += alloc_size;
  return val;
}

llvm::Value *CallingConvention::LoadNextArgument(llvm::BasicBlock *block,
                                                 llvm::Type *target_type,
                                                 bool is_byval) {
  if (!target_type) {
    target_type = gWordType;
  }

  llvm::IRBuilder<> ir(block);

  std::vector<llvm::Value*> underlying_values;
  llvm::Type *goal_type = target_type;

  if (target_type->isPointerTy() && !is_byval) {
    return LoadNextSimpleArgument(block, target_type);
  }
  if (auto struct_type = llvm::dyn_cast<llvm::StructType>(goal_type)) {
    std::vector<llvm::Value*> underlying_values;
    for (unsigned i = 0; i < struct_type->getNumElements(); ++i) {
      llvm::Type *under_type = struct_type->getElementType(i);
      underlying_values.push_back(
          LoadNextSimpleArgument(block, under_type));
    }

    llvm::IRBuilder<> ir(block);
    auto alloca = ir.CreateAlloca(target_type);
    for (unsigned i = 0; i < underlying_values.size(); ++i) {
      auto gep = ir.CreateGEP(alloca,
          {GetConstantInt(64, 0), GetConstantInt(64, i)});
      ir.CreateStore(underlying_values[i], gep);
    }
    return ir.CreateLoad(alloca);
  } else if (is_byval) {
    // byval attribute says that caller makes a copy of argument on the stack
    auto stack_ptr = LoadStackPointer(block);
    auto offset = llvm::ConstantInt::get(gWordType, num_loaded_stack_bytes);
    auto addr = ir.CreateAdd(stack_ptr, offset);

    llvm::DataLayout dl(gModule);
    auto ptr_type = llvm::dyn_cast<llvm::PointerType>(target_type);

    num_loaded_stack_bytes += dl.getTypeAllocSize(ptr_type->getElementType());
    return ir.CreateIntToPtr(addr, target_type);
  }
  return LoadNextSimpleArgument(block, target_type);
}


void ExtractFromVector(llvm::BasicBlock *block,
                              llvm::Value *ret_val,
                              llvm::Value *reg_ptr,
                              size_t count, size_t start=0) {

  llvm::IRBuilder<> ir(block);

  for (size_t i = 0; i < count; ++i) {
    auto offset = ir.CreateGEP(reg_ptr, GetConstantInt(64, i));
    auto extract = ir.CreateExtractElement(ret_val,
        GetConstantInt(64, i + start));
    ir.CreateStore(extract, offset);
  }
}

void CallingConvention::StoreVectorRetValue(llvm::BasicBlock *block,
                                            llvm::Value *ret_val,
                                            llvm::VectorType *goal_type) {
  llvm::IRBuilder<> ir(block);
  auto under_type = goal_type->getElementType();
  auto num_elements = goal_type->getNumElements();

  size_t reg_size = GetVectorRegSize();
  llvm::DataLayout dl(gModule);

  uint64_t element_size = dl.getTypeAllocSize(under_type);
  size_t reg_element_capacity = reg_size / element_size;
  int32_t remaining = static_cast<int32_t>(num_elements);

  for ( unsigned i = 0; remaining > 0; ++i, remaining -= reg_element_capacity) {
    auto reg_var_name = GetVarForNextReturn(goal_type);
    llvm::Value *dest_loc = remill::FindVarInFunction(block, reg_var_name);

    // Clear out whatever was already there
    auto storage_type = llvm::dyn_cast<llvm::PointerType>(
        dest_loc->getType())->getElementType();
    ir.CreateStore(llvm::Constant::getNullValue(storage_type), dest_loc);

    dest_loc = ir.CreateBitCast(dest_loc,
        llvm::PointerType::get(under_type, 0));

    auto count = std::min(reg_element_capacity, static_cast<size_t>(remaining));
    ExtractFromVector(block, ret_val, dest_loc, count , i * reg_element_capacity);
  }
}

void CallingConvention::StoreReturnValue(llvm::BasicBlock *block,
                                         llvm::Value *ret_val) {
  if (!ret_val) {
    return;
  }

  auto val_type = ret_val->getType();
  if (val_type->isVoidTy()) {
    return;
  }

  llvm::IRBuilder<> ir(block);

  for (unsigned i = 0; i < GetNumberOfElements(val_type); ++i) {
    llvm::Value* target_val = ret_val;

    if (val_type->isStructTy()) {
      target_val = ir.CreateExtractValue(ret_val, i);
    }
    auto under_type = RetrieveArgumentType(val_type, i);

    if (auto vector_type = llvm::dyn_cast<llvm::VectorType>(under_type)) {
      StoreVectorRetValue(block, target_val, vector_type);
      continue;
    }

    //auto val_var = ReturnValVar(cc, under_type, i);
    auto val_var = GetVarForNextReturn(under_type);

    // If it's a pointer then convert it to a pointer-sized integer.
    if (under_type->isPointerTy()) {
      target_val = ir.CreatePtrToInt(target_val, gWordType);
      under_type = gWordType;
    }

    // If it's an 80-bit float then convert it to a double.
    if (under_type->isX86_FP80Ty()) {
      under_type = llvm::Type::getDoubleTy(*gContext);
      target_val = ir.CreateFPTrunc(target_val, under_type);
    }

    CHECK(under_type->isIntegerTy() || under_type->isFloatTy() ||
          under_type->isDoubleTy());

    llvm::DataLayout dl(gModule);

    // Canonicalize integer return values into address-sized values.
    if (under_type->isIntegerTy()) {
      auto size = dl.getTypeSizeInBits(under_type);
      if (size < gArch->address_size) {
        under_type = gWordType;
        target_val = ir.CreateZExt(target_val, under_type);

      } else if (size > gArch->address_size) {
        LOG(ERROR)
            << "Truncating value of type "
            << remill::LLVMThingToString(under_type)
            << " to store it into variable " << val_var
            << " of type " << remill::LLVMThingToString(gWordType);
        target_val = ir.CreateTrunc(target_val, gWordType);
        under_type = gWordType;
      }

    // Storing a `float` into an x87 register, convert it to a `double`.
    } else if (under_type->isFloatTy()) {
      if (val_var && val_var[0] == 'S' && val_var[1] == 'T') {
        under_type = llvm::Type::getDoubleTy(*gContext);
        target_val = ir.CreateFPExt(target_val, under_type);
      }
    }

    llvm::Value *dest_loc = remill::FindVarInFunction(block, val_var);

    // Clear out whatever was already there.
    auto storage_type = llvm::dyn_cast<llvm::PointerType>(
        dest_loc->getType())->getElementType();
    ir.CreateStore(llvm::Constant::getNullValue(storage_type), dest_loc);

    // Add in the new value.
    dest_loc = ir.CreateBitCast(dest_loc, llvm::PointerType::get(under_type, 0));
    ir.CreateStore(target_val, dest_loc);
  }

}

void CallingConvention::StoreArguments(
    llvm::BasicBlock *block, const std::vector<llvm::Value *> &arg_vals) {

  auto memory_ref = remill::LoadMemoryPointerRef(block);

  llvm::IRBuilder<> ir(block);
  std::vector<llvm::Value *> stack_arg_vals;

  // First try to put as many as possible into registers.
  for (auto arg_val : arg_vals) {
    auto arg_type = arg_val->getType();
    if (auto reg_var_name = GetVarForNextArgument(arg_type)) {
      auto reg_ptr = remill::FindVarInFunction(block, reg_var_name);
      ir.CreateStore(
          arg_val,
          ir.CreateBitCast(reg_ptr, llvm::PointerType::get(arg_type, 0)));
    } else {
      stack_arg_vals.push_back(arg_val);
    }
  }

  // Now we have some left that need to be pushed onto the stack. We're going
  // to push them onto the stack in reverse order.
  CHECK(gArch->IsX86() || gArch->IsAMD64() || gArch->IsAArch64());
  std::reverse(stack_arg_vals.begin(), stack_arg_vals.end());

  auto addr_size = gArch->address_size / 8;
  auto sp = LoadStackPointer(block);
  llvm::Value *memory = ir.CreateLoad(memory_ref);

  llvm::DataLayout dl(gModule);

  std::vector<llvm::Value *> args(3, nullptr);

  for (auto arg_val : stack_arg_vals) {
    auto arg_type = arg_val->getType();
    auto alloc_size = dl.getTypeAllocSize(arg_type);
    llvm::Function *func = nullptr;

    if (arg_type->isX86_FP80Ty()) {
      func = gModule->getFunction("__remill_write_memory_f80");
      arg_val = ir.CreateFPTrunc(arg_val, llvm::Type::getDoubleTy(*gContext));

    } else if (arg_type->isDoubleTy()) {
      func = gModule->getFunction("__remill_write_memory_f64");

    } else if (arg_type->isFloatTy()) {
      func = gModule->getFunction("__remill_write_memory_f32");

    } else if (arg_type->isIntegerTy()) {
      func = WriteIntToMemFunc(alloc_size);

      if (dl.getTypeSizeInBits(arg_type) <
          dl.getTypeAllocSizeInBits(arg_type)) {
        arg_type = llvm::Type::getIntNTy(
            *gContext, static_cast<unsigned>(alloc_size * 8));
        arg_val = ir.CreateZExt(arg_val, arg_type);
      }

    } else if (arg_type->isPointerTy()) {
      if (32 == gArch->address_size) {
        func = gModule->getFunction("__remill_write_memory_32");
      } else {
        func = gModule->getFunction("__remill_write_memory_64");
      }
      arg_val = ir.CreatePtrToInt(arg_val, gWordType);
    }

    CHECK(func != nullptr)
        << "Could not find remill memory write intrinsic to write a "
        << alloc_size << "-byte value of type "
        << remill::LLVMThingToString(arg_type) << " to the stack.";

    // Store the argument to the stack memory.
    args[0] = memory;
    args[1] = sp;
    args[2] = arg_val;
    memory = ir.CreateCall(func, args);

    // Bump the stack pointer.
    alloc_size = std::max<uint64_t>(alloc_size, addr_size);
    sp = ir.CreateSub(sp, llvm::ConstantInt::get(gWordType, alloc_size));
    num_stored_stack_bytes += alloc_size;
  }

  ir.CreateStore(memory, memory_ref);  // Update the memory pointer.

  StoreStackPointer(block, sp);
}

void CallingConvention::FreeArguments(llvm::BasicBlock *block) {
  if (!num_stored_stack_bytes) {
    return;
  }

  if (llvm::CallingConv::X86_StdCall == cc ||
      llvm::CallingConv::X86_ThisCall == cc) {
    return;  // Callee cleanup.
  }

  auto sp = LoadStackPointer(block);

  llvm::IRBuilder<> ir(block);
  sp = ir.CreateAdd(
      sp, llvm::ConstantInt::get(gWordType, num_stored_stack_bytes));

  StoreStackPointer(block, sp);
}

void CallingConvention::AllocateReturnAddress(llvm::BasicBlock *block) {
  if (gArch->IsAArch64()) {
    return;  // Return address is passed through the link pointer.

  // The stack grows down on x86/amd64.
  } else if (gArch->IsX86() || gArch->IsAMD64()) {
    llvm::IRBuilder<> ir(block);

    auto addr_size = gArch->address_size / 8;

    if (llvm::CallingConv::Win64 == cc) {
      CHECK(gArch->IsAMD64());
      addr_size += 32;  // Shadow space.
    }

    auto addr_size_bytes = llvm::ConstantInt::get(gWordType, addr_size);
    StoreStackPointer(
        block, ir.CreateSub(LoadStackPointer(block), addr_size_bytes));

  } else {
    LOG(FATAL)
        << "Cannot allocate space for return address for architecture "
        << remill::GetArchName(gArch->arch_name) << " and calling convention "
        << cc;
  }
}

void CallingConvention::FreeReturnAddress(llvm::BasicBlock *block) {
  if (gArch->IsAArch64()) {
    auto x30 = remill::FindVarInFunction(block, "X30");
    llvm::IRBuilder<> ir(block);
    auto ret_addr = ir.CreateLoad(x30);
    remill::StoreProgramCounter(block, ret_addr);

  // The stack grows down on x86/amd64.
  } else if (gArch->IsX86() || gArch->IsAMD64()) {
    llvm::IRBuilder<> ir(block);
    auto addr_size = gArch->address_size / 8;
    auto addr_size_bytes = llvm::ConstantInt::get(gWordType, addr_size);
    auto sp = LoadStackPointer(block);
    auto read_ret_addr = ReadIntFromMemFunc(addr_size);
    llvm::Value *read_ret_addr_args[] = {remill::LoadMemoryPointer(block), sp};
    auto ret_addr = ir.CreateCall(read_ret_addr, read_ret_addr_args);
    remill::StoreProgramCounter(block, ret_addr);

    StoreStackPointer(
        block, ir.CreateAdd(sp, addr_size_bytes));

  } else {
    LOG(FATAL)
        << "Cannot allocate space for return address for architecture "
        << remill::GetArchName(gArch->arch_name) << " and calling convention "
        << cc;
  }
}

llvm::Value *CallingConvention::LoadReturnValue(llvm::BasicBlock *block,
                                                llvm::Type *val_type) {
  llvm::IRBuilder<> ir(block);

  if (!val_type) {
    val_type = gWordType;
  }

  //auto val_var = ReturnValVar(cc, val_type);
  auto val_var = GetVarForNextReturn(val_type);
  return ir.CreateLoad(ir.CreateBitCast(
      remill::FindVarInFunction(block, val_var),
      llvm::PointerType::get(val_type, 0)));
}

llvm::Value *CallingConvention::LoadStackPointer(llvm::BasicBlock *block) {
  llvm::IRBuilder<> ir(block);
  return ir.CreateLoad(remill::FindVarInFunction(block, sp_name, false));
}

void CallingConvention::StoreStackPointer(llvm::BasicBlock *block,
                                          llvm::Value *new_val) {
  llvm::IRBuilder<> ir(block);
  auto val_type = new_val->getType();
  if (val_type->isPointerTy()) {
    new_val = ir.CreatePtrToInt(new_val, gWordType);
  }
  ir.CreateStore(
      new_val,
      remill::FindVarInFunction(block, StackPointerVarName()));
}

void CallingConvention::StoreThreadPointer(llvm::BasicBlock *block,
                                           llvm::Value *new_val) {
  llvm::IRBuilder<> ir(block);
  auto val_type = new_val->getType();
  if (val_type->isPointerTy()) {
    new_val = ir.CreatePtrToInt(new_val, gWordType);
  }
  ir.CreateStore(
      new_val,
      remill::FindVarInFunction(block, ThreadPointerVarName()));
}

// Return the address of the base of the TLS data.
llvm::Value *GetTLSBaseAddress(llvm::IRBuilder<> &ir) {
  enum {
    kGSAddressSpace = 256U,
    kFSAddressSpace = 257U,

    // From inside of the TEB.
    kWin32TLSPointerIndex = 0x2c,
    kWin64TLSPointerIndex = 0x58
  };

  if (gArch->IsAArch64()) {

#if LLVM_VERSION(3, 7) >= LLVM_VERSION_NUMBER
    LOG(ERROR)
        << "LLVM 3.7 and below have no AArch64 thread pointer-related "
        << "intrinsics; using NULL as the base of TLS.";
    return llvm::ConstantInt::get(gWordType, 0);

#elif LLVM_VERSION(3, 8) >= LLVM_VERSION_NUMBER
    LOG(ERROR)
        << "Assuming the `llvm.arm.thread.pointer` intrinsic gets us the base "
        << "of thread-local storage.";
    auto func = llvm::Intrinsic::getDeclaration(
        gModule, llvm::Intrinsic::arm_thread_pointer);
    return ir.CreatePtrToInt(ir.CreateCall(func), gWordType);
#else
    LOG(ERROR)
        << "Assuming the `thread.pointer` intrinsic gets us the base "
        << "of thread-local storage.";
    auto func = llvm::Intrinsic::getDeclaration(
        gModule, llvm::Intrinsic::thread_pointer);
    return ir.CreatePtrToInt(ir.CreateCall(func), gWordType);
#endif

  // 64-bit x86.
  } else if (gArch->IsAMD64()) {
    llvm::ConstantInt *base = nullptr;
    unsigned addr_space = 0;
    if (remill::kOSWindows == gArch->os_name) {
      base = llvm::ConstantInt::get(gWordType, kWin64TLSPointerIndex);
      addr_space = kGSAddressSpace;
    } else if (remill::kOSLinux == gArch->os_name) {
      base = llvm::ConstantInt::get(gWordType, 0);
      addr_space = kFSAddressSpace;
    }

    if (base) {
      auto tls_base_ptr = ir.CreateIntToPtr(
          base, llvm::PointerType::get(gWordType, addr_space));
      return ir.CreateLoad(tls_base_ptr);
    }

  // 32-bit x86.
  } else if (gArch->IsX86()) {
    llvm::ConstantInt *base = nullptr;
    unsigned addr_space = 0;
    if (remill::kOSWindows == gArch->os_name) {
      base = llvm::ConstantInt::get(gWordType, kWin32TLSPointerIndex);
      addr_space = kFSAddressSpace;
    } else if (remill::kOSLinux == gArch->os_name) {
      base = llvm::ConstantInt::get(gWordType, 0);
      addr_space = kGSAddressSpace;
    }

    if (base) {
      auto tls_base_ptr = ir.CreateIntToPtr(
          base, llvm::PointerType::get(gWordType, addr_space));
      return ir.CreateLoad(tls_base_ptr);
    }
  }

  LOG(FATAL)
      << "Cannot generate code to find the thread base pointer for arch "
      << remill::GetArchName(gArch->arch_name) << " and OS "
      << remill::GetOSName(gArch->os_name);
  return nullptr;
}

}  // namespace mcsema
