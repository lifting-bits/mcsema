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

#include "mcsema/BC/Util.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wswitch-enum"
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#pragma clang diagnostic pop

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Compat/GlobalValue.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>

#include <string>

#include "mcsema/Arch/Arch.h"

DEFINE_bool(
    disable_aliases, false,
    "Disable using global aliases for accessing data/registers in the bitcode");

namespace mcsema {

std::shared_ptr<llvm::LLVMContext> gContext = nullptr;
llvm::IntegerType *gWordType = nullptr;
uint64_t gWordMask = 0;
std::unique_ptr<llvm::Module> gModule = nullptr;
llvm::Constant *gZero = nullptr;

llvm::Value *GetConstantInt(unsigned size, uint64_t value) {
  return llvm::ConstantInt::get(llvm::Type::getIntNTy(*gContext, size), value);
}

// Get a lifted representation of a reference (in code) to `ea`.
llvm::Constant *LiftXrefInCode(uint64_t ea) {
  return llvm::ConstantExpr::getAdd(
      gZero, llvm::ConstantInt::get(gWordType, ea & gWordMask, false));
}

// Get a lifted representation of a reference (in data) to `ea`.
llvm::Constant *LiftXrefInData(const NativeSegment *cfg_seg, uint64_t ea,
                               bool cast_to_int) {
  CHECK(cfg_seg != nullptr);
  CHECK(cfg_seg->ea <= ea);
  CHECK(ea < (cfg_seg->ea + cfg_seg->size));

  std::stringstream ss;
  ss << "data_" << std::hex << ea;
  auto alias_name = ss.str();

  llvm::Constant *ptr = nullptr;
  if (auto alias = gModule->getNamedAlias(alias_name); alias) {
    ptr = alias;

  } else {
    auto seg_var =
        llvm::dyn_cast<llvm::GlobalVariable>(cfg_seg->Get()->Pointer());

    auto seg_type = remill::GetValueType(seg_var);
    llvm::DataLayout dl(gModule.get());

    llvm::SmallVector<llvm::Value *, 8> gep_index_list;
    auto i32_type = llvm::Type::getInt32Ty(*gContext);
    gep_index_list.push_back(llvm::ConstantInt::get(i32_type, 0));
    const auto goal_offset = (ea - cfg_seg->ea) + cfg_seg->padding;
    auto [offset, type] =
        remill::BuildIndexes(dl, seg_type, 0, goal_offset, gep_index_list);

    ptr = llvm::ConstantExpr::getInBoundsGetElementPtr(seg_type, seg_var,
                                                       gep_index_list);

    if (offset < goal_offset) {
      auto i8_type = llvm::Type::getInt8Ty(*gContext);
      ptr = llvm::ConstantExpr::getBitCast(ptr,
                                           llvm::PointerType::get(i8_type, 0));
      ptr = llvm::ConstantExpr::getInBoundsGetElementPtr(
          i8_type, ptr,
          llvm::ConstantInt::get(i32_type, goal_offset - offset, false));
    }

    if (!FLAGS_disable_aliases && !cfg_seg->is_external) {
      auto ptr_type = llvm::dyn_cast<llvm::PointerType>(ptr->getType());
      ptr = llvm::GlobalAlias::create(
          ptr_type->getElementType(), ptr_type->getAddressSpace(),
          seg_var->getLinkage(), alias_name, ptr, gModule.get());
    }
  }

  if (cast_to_int) {
    return llvm::ConstantExpr::getPtrToInt(ptr, gWordType);
  } else {
    return ptr;
  }
}

// Create a global register state pointer to pass to lifted functions.
llvm::Constant *GetStatePointer(void) {
  static llvm::Constant *state_ptr = nullptr;
  if (state_ptr) {
    return state_ptr;
  }

  auto state_type = gArch->StateStructType();

  // State is initialized with zeroes. Each callback/entrypoint set
  // appropriate value to stack pointer. This is needed because of
  // thread_local
  auto state_init = llvm::ConstantAggregateZero::get(state_type);
  const auto state_ptr_var = new llvm::GlobalVariable(
      *gModule, state_type, false, llvm::GlobalValue::ExternalLinkage,
      state_init, "__mcsema_reg_state", nullptr,
      llvm::GlobalValue::InitialExecTLSModel);

  state_ptr = state_ptr_var;
  if (state_ptr_var->getType()->getPointerAddressSpace() != 0) {
    state_ptr = llvm::ConstantExpr::getAddrSpaceCast(
        state_ptr, llvm::PointerType::get(state_type, 0));
  }

  return state_ptr;
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
    LOG(ERROR) << "LLVM 3.7 and below have no thread pointer-related "
               << "intrinsics; using NULL as the base of TLS.";
    return llvm::ConstantInt::get(gWordType, 0);
#else
#  if LLVM_VERSION(3, 8) >= LLVM_VERSION_NUMBER
    if (gArch->IsAArch64()) {
      LOG(ERROR)
          << "Assuming the `llvm.arm.thread.pointer` intrinsic gets us the base "
          << "of thread-local storage.";
      auto func = llvm::Intrinsic::getDeclaration(
          gModule.get(), llvm::Intrinsic::arm_thread_pointer);
      if (func) {
        return ir.CreatePtrToInt(ir.CreateCall(func), gWordType);
      }
    }
#  endif
    LOG(ERROR) << "Assuming the `thread.pointer` intrinsic gets us the base "
               << "of thread-local storage.";
    auto func = llvm::Intrinsic::getDeclaration(
        gModule.get(), llvm::Intrinsic::thread_pointer);
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

  LOG(FATAL) << "Cannot generate code to find the thread base pointer for arch "
             << remill::GetArchName(gArch->arch_name) << " and OS "
             << remill::GetOSName(gArch->os_name);
  return nullptr;
}

}  // namespace mcsema
