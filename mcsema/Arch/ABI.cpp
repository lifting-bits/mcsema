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

  kIntegralLeast32 = kI8 | kI16 | kI32,
  kIntegralLeast64 = kI8 | kI16 | kI32 | kI64,
};

struct ArgConstraint {
  const char *var_name;
  const int accepted_val_kinds;
};

namespace {

static ValueKind KindOfValue(llvm::Type *type) {
  if (!type || type->isPointerTy()) {
    return (32 == gArch->address_size) ? kI32 : kI64;

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

static const ArgConstraint *ConstraintTable(llvm::CallingConv::ID cc) {
  static const ArgConstraint kNoArgs[] = {
     {nullptr, kInvalidKind},
 };

  if (llvm::CallingConv::X86_64_SysV == cc) {
    static const ArgConstraint kAmd64SysVArgs[] = {
        {"RDI", kIntegralLeast64},
        {"RSI", kIntegralLeast64},
        {"RDX", kIntegralLeast64},
        {"RCX", kIntegralLeast64},
        {"R8", kIntegralLeast64},
        {"R9", kIntegralLeast64},
        {"XMM0", kF32 | kF64},
        {"XMM1", kF32 | kF64},
        {"XMM2", kF32 | kF64},
        {"XMM3", kF32 | kF64},
        {"XMM4", kF32 | kF64},
        {"XMM5", kF32 | kF64},
        {"XMM6", kF32 | kF64},
        {"XMM7", kF32 | kF64},
        {"XMM8", kF32 | kF64},
        {"XMM9", kF32 | kF64},
        {"XMM10", kF32 | kF64},
        {"XMM11", kF32 | kF64},
        {"XMM12", kF32 | kF64},
        {"XMM13", kF32 | kF64},
        {"XMM14", kF32 | kF64},
        {"XMM15", kF32 | kF64},
        {nullptr, kInvalidKind},
    };
    return &(kAmd64SysVArgs[0]);

  } else if (llvm::CallingConv::Win64 == cc) {
    static const ArgConstraint kAmd64Win64Args[] = {
        {"RCX", kIntegralLeast64},
        {"RDX", kIntegralLeast64},
        {"R8", kIntegralLeast64},
        {"R9", kIntegralLeast64},
        {"XMM0", kF32 | kF64},
        {"XMM1", kF32 | kF64},
        {"XMM2", kF32 | kF64},
        {"XMM3", kF32 | kF64},
        {nullptr, kInvalidKind},
    };
    return &(kAmd64Win64Args[0]);

  } else if (llvm::CallingConv::X86_FastCall == cc) {
    static const ArgConstraint kX86FastCallArgs[] = {
        {"ECX", kIntegralLeast32},
        {"EDX", kIntegralLeast32},
        {nullptr, kInvalidKind},
    };
    return &(kX86FastCallArgs[0]);

  } else if (llvm::CallingConv::X86_ThisCall == cc) {
    static const ArgConstraint kX86ThisCallArgs[] = {
        {"ECX", kIntegralLeast32},
        {nullptr, kInvalidKind},
    };
    return &(kX86ThisCallArgs[0]);

  } else if (llvm::CallingConv::X86_StdCall == cc) {
    return &(kNoArgs[0]);  // stdcall takes all args on the stack.

  } else if (llvm::CallingConv::C == cc) {
    if (gArch->IsX86()) {
      return &(kNoArgs[0]);  // cdecl takes all args on the stack.

    } else if (gArch->IsAArch64()) {
      static const ArgConstraint kAArch64Args[] = {
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
      return &(kAArch64Args[0]);
    }
  }

  LOG(FATAL)
      << "Unknown ABI/calling convention: " << cc;
  return &(kNoArgs[0]);
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

static const char *IntReturnValVar(llvm::CallingConv::ID cc) {
  if (llvm::CallingConv::X86_64_SysV == cc ||
      llvm::CallingConv::Win64 == cc) {
    return "RAX";

  } else if (llvm::CallingConv::X86_StdCall == cc ||
             llvm::CallingConv::X86_FastCall == cc ||
             llvm::CallingConv::X86_ThisCall == cc) {
    return "EAX";

  } else if (llvm::CallingConv::C == cc) {
    if (gArch->IsX86()) {
      return "EAX";  // cdecl.

    } else if (gArch->IsAArch64()) {
      return "X0";
    }
  }

  LOG(FATAL)
      << "Unknown ABI/calling convention: " << cc;
  return nullptr;
}

static const char *FloatReturnValVar(llvm::CallingConv::ID cc,
                                     llvm::Type *type) {
  if (llvm::CallingConv::X86_64_SysV == cc ||
      llvm::CallingConv::Win64 == cc) {
    return "XMM0";

  } else if (llvm::CallingConv::X86_StdCall == cc ||
             llvm::CallingConv::X86_FastCall == cc ||
             llvm::CallingConv::X86_ThisCall == cc) {
    return "ST0";

  } else if (llvm::CallingConv::C == cc) {
    if (gArch->IsX86()) {
      return "EAX";  // cdecl.

    } else if (gArch->IsAArch64()) {
      if (type->isDoubleTy()) {
        return "D0";
      } else {
        CHECK(type->isFloatTy());
        return "S0";
      }
    }
  }

  LOG(FATAL)
      << "Cannot decide where to put return value of type "
      << remill::LLVMThingToString(type) << " for calling convention "
      << cc;

  return nullptr;
}

static const char *ReturnValVar(llvm::CallingConv::ID cc, llvm::Type *type) {
  if (type->isPointerTy() || type->isIntegerTy()) {
    return IntReturnValVar(cc);
  } else if (type->isX86_FP80Ty()) {
    return "ST0";
  } else if (type->isFloatTy() || type->isDoubleTy()) {
    return FloatReturnValVar(cc, type);
  } else {
    LOG(FATAL)
        << "Cannot decide where to put return value of type "
        << remill::LLVMThingToString(type) << " for calling convention "
        << cc;
    return nullptr;
  }
}

}  // namespace

CallingConvention::CallingConvention(llvm::CallingConv::ID cc_)
    : cc(cc_),
      used_reg_bitmap(0),
      num_loaded_stack_bytes(DefaultUsedStackBytes(cc)),
      num_stored_stack_bytes(0),
      sp_name(StackPointerName()),
      tp_name(ThreadPointerName()),
      reg_table(ConstraintTable(cc)) {}

// Scan through the register table. If we can match this argument request
// to a register then do so.
const char *CallingConvention::GetVarForNextArgument(llvm::Type *val_type) {
  auto val_kind = KindOfValue(val_type);
  for (uint64_t i = 0; ; ++i) {
    const auto &reg_loc = reg_table[i];
    if (!reg_loc.var_name) {
      break;
    }
    if (val_kind == (reg_loc.accepted_val_kinds & val_kind)) {
      auto mask = 1ULL << i;
      if (!(used_reg_bitmap & mask)) {
        used_reg_bitmap |= mask;
        return reg_loc.var_name;
      }
    }
  }
  return nullptr;
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

llvm::Value *CallingConvention::LoadNextArgument(llvm::BasicBlock *block,
                                                 llvm::Type *goal_type) {
  if (!goal_type) {
    goal_type = gWordType;
  }

  llvm::IRBuilder<> ir(block);

  if (auto reg_var_name = GetVarForNextArgument(goal_type)) {
    auto reg_ptr_ptr = remill::FindVarInFunction(block, reg_var_name);
    auto reg_ptr = ir.CreateLoad(reg_ptr_ptr);
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
  auto val_var = ReturnValVar(cc, val_type);

  // If it's a pointer then convert it to a pointer-sized integer.
  if (val_type->isPointerTy()) {
    ret_val = ir.CreatePtrToInt(ret_val, gWordType);
    val_type = gWordType;
  }

  // If it's an 80-bit float then convert it to a double.
  if (val_type->isX86_FP80Ty()) {
    val_type = llvm::Type::getDoubleTy(*gContext);
    ret_val = ir.CreateFPTrunc(ret_val, val_type);
  }

  CHECK(val_type->isIntegerTy() || val_type->isFloatTy() ||
        val_type->isDoubleTy());

  llvm::DataLayout dl(gModule);

  // Canonicalize integer return values into address-sized values.
  if (val_type->isIntegerTy()) {
    auto size = dl.getTypeSizeInBits(val_type);
    if (size < gArch->address_size) {
      val_type = gWordType;
      ret_val = ir.CreateZExt(ret_val, val_type);

    } else if (size > gArch->address_size) {
      LOG(ERROR)
          << "Truncating value of type "
          << remill::LLVMThingToString(val_type)
          << " to store it into variable " << val_var
          << " of type " << remill::LLVMThingToString(gWordType);
      ret_val = ir.CreateTrunc(ret_val, gWordType);
      val_type = gWordType;
    }

  // Storing a `float` into an x87 register, convert it to a `double`.
  } else if (val_type->isFloatTy()) {
    if (val_var && !strcmp("ST0", val_var)) {
      val_type = llvm::Type::getDoubleTy(*gContext);
      ret_val = ir.CreateFPExt(ret_val, val_type);
    }
  }

  llvm::Value *dest_loc = ir.CreateLoad(
      remill::FindVarInFunction(block, val_var));

  // Clear out whatever was already there.
  auto storage_type = llvm::dyn_cast<llvm::PointerType>(
      dest_loc->getType())->getElementType();
  ir.CreateStore(llvm::Constant::getNullValue(storage_type), dest_loc);

  // Add in the new value.
  dest_loc = ir.CreateBitCast(dest_loc, llvm::PointerType::get(val_type, 0));
  ir.CreateStore(ret_val, dest_loc);
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
      auto reg_ptr_ptr = remill::FindVarInFunction(block, reg_var_name);
      auto reg_ptr = ir.CreateLoad(reg_ptr_ptr);
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
    auto ret_addr = ir.CreateLoad(ir.CreateLoad(x30));
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

  auto val_var = ReturnValVar(cc, val_type);
  return ir.CreateLoad(ir.CreateBitCast(
      ir.CreateLoad(remill::FindVarInFunction(block, val_var)),
      llvm::PointerType::get(val_type, 0)));
}

llvm::Value *CallingConvention::LoadStackPointer(llvm::BasicBlock *block) {
  llvm::IRBuilder<> ir(block);
  return ir.CreateLoad(ir.CreateLoad(
      remill::FindVarInFunction(block, sp_name)));
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
      ir.CreateLoad(remill::FindVarInFunction(block, StackPointerVarName())));
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
      ir.CreateLoad(remill::FindVarInFunction(block, ThreadPointerVarName())));
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
