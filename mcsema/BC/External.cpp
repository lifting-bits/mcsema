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

#include "mcsema/BC/External.h"

#include <anvill/Decl.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wswitch-enum"
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#pragma clang diagnostic pop

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Annotate.h>

#include <sstream>
#include <vector>

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Callback.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

DECLARE_bool(explicit_args);

namespace mcsema {

llvm::Constant *NativeExternalFunction::Pointer(void) const {
  const auto prev_function = function;
  function = gModule->getFunction(name);
  if (!function && decl) {
    function = decl->DeclareInModule(name, *gModule);
    if (!prev_function) {
      module->AddNameToAddress(name, ea);
    }
  }

  if (function) {

    if (function == prev_function) {
      return prev_function;
    }

    // The function exists and isn't varargs; use it.
    if (is_weak) {
      if (function->isDeclaration()) {
        function->setLinkage(llvm::GlobalValue::ExternalWeakLinkage);
      } else {
        function->setLinkage(llvm::GlobalValue::AvailableExternallyLinkage);
      }
    } else {
      function->setLinkage(llvm::GlobalValue::ExternalLinkage);
    }

    remill::Annotate<remill::CFGExternal>(function);

    return function;

  // The function doesn't exist in the module, and we need to declare it with
  // the information we have from CFG extraction.
  } else {
    CHECK(is_external);
    std::vector<llvm::Type *> param_types(num_args, gWordType);

    module->AddNameToAddress(name, ea);

    function = llvm::Function::Create(
        llvm::FunctionType::get(gWordType, param_types, false),
        llvm::GlobalValue::ExternalLinkage, name, gModule.get());

    if (is_weak) {
      function->setLinkage(llvm::GlobalValue::ExternalWeakLinkage);
    }

    function->setCallingConv(cc);

    function->removeFnAttr(llvm::Attribute::InlineHint);
    function->removeFnAttr(llvm::Attribute::AlwaysInline);
    function->removeFnAttr(llvm::Attribute::ReadNone);
    function->removeFnAttr(llvm::Attribute::ReadOnly);
    function->removeFnAttr(llvm::Attribute::ArgMemOnly);

    function->addFnAttr(llvm::Attribute::NoInline);
    function->addFnAttr(llvm::Attribute::NoBuiltin);

    remill::Annotate<remill::CFGExternal>(function);
    return function;
  }
}

llvm::Constant *NativeExternalVariable::Pointer(void) const {
  CHECK(is_external);
  CHECK_NOTNULL(segment);
  const auto seg = segment->Get();
  CHECK(seg->is_external);
  CHECK_EQ(ea, seg->ea);
  CHECK(!seg->padding);
  return seg->Pointer();
}

llvm::Constant *NativeExternalVariable::Address(void) const {
  return llvm::ConstantExpr::getPtrToInt(Pointer(), gWordType);
}

}  // namespace mcsema
