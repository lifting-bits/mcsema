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

#include <string>

#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"
#include "remill/OS/OS.h"

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Util.h"

namespace mcsema {

llvm::LLVMContext *gContext = nullptr;
llvm::IntegerType *gWordType = nullptr;
llvm::Module *gModule = nullptr;

// Return the type of a lifted function.
llvm::FunctionType *LiftedFunctionType(void) {
  static llvm::FunctionType *func_type = nullptr;
  if (!func_type) {
    func_type = remill::LiftedFunctionType(gModule);
  }
  return func_type;
}

// Translate `ea` into an LLVM value that is an address that points into the
// lifted segment associated with `seg`.
llvm::Constant *LiftEA(const NativeSegment *cfg_seg, uint64_t ea) {
  CHECK(cfg_seg != nullptr);
  CHECK(cfg_seg->ea <= ea);
  CHECK(ea < (cfg_seg->ea + cfg_seg->size));

  auto seg = gModule->getGlobalVariable(cfg_seg->lifted_name, true);
  CHECK(seg != nullptr)
      << "Cannot find global variable for segment " << cfg_seg->name
      << " when trying to lift EA " << std::hex << ea;

  auto offset = ea - cfg_seg->ea;
  return llvm::ConstantExpr::getAdd(
      llvm::ConstantExpr::getPtrToInt(seg, gWordType),
      llvm::ConstantInt::get(gWordType, offset));
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
