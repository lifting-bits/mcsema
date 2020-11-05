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

#include "mcsema/Arch/Arch.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wswitch-enum"
#include <glog/logging.h>
#include <llvm/ADT/ArrayRef.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>
#pragma clang diagnostic pop

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#include <unordered_set>

#include "mcsema/BC/Util.h"

namespace mcsema {

extern std::shared_ptr<llvm::LLVMContext> gContext;

std::unique_ptr<const remill::Arch> gArch(nullptr);

bool InitArch(const std::string &os, const std::string &arch) {
  LOG(INFO) << "Initializing for " << arch << " code on " << os;

  auto os_name = remill::GetOSName(os);
  auto arch_name = remill::GetArchName(arch);

  remill::Arch::Build(gContext.get(), os_name, arch_name).swap(gArch);
  gWordType = llvm::Type::getIntNTy(*gContext,
                                    static_cast<unsigned>(gArch->address_size));

  gWordMask = 0;
  if (32 == gArch->address_size) {
    gWordMask = static_cast<uint32_t>(~0u);
  } else {
    gWordMask = ~gWordMask;
  }

  return true;
}

}  // namespace mcsema
