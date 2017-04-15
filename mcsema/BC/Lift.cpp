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

#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Type.h>

#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/BC/ABI.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Lifter.h"

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/External.h"
#include "mcsema/BC/Function.h"
#include "mcsema/BC/Lift.h"
#include "mcsema/BC/Optimize.h"
#include "mcsema/BC/Segment.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"


namespace mcsema {
namespace {
//
//llvm::CallingConv::ID getLLVMCC(ExternalCodeRef::CallingConvention cc) {
//  switch (cc) {
//    case ExternalCodeRef::CallerCleanup:
//      return llvm::CallingConv::C;
//    case ExternalCodeRef::CalleeCleanup:
//      return llvm::CallingConv::X86_StdCall;
//    case ExternalCodeRef::FastCall:
//      return llvm::CallingConv::X86_FastCall;
//    case ExternalCodeRef::McsemaCall:
//      // mcsema internal calls are cdecl with one argument
//      return llvm::CallingConv::C;
//    default:
//      LOG(FATAL)
//          << "Unknown calling convention.";
//  }
//
//  return llvm::CallingConv::C;
//}

//
// common case for arithmetic instructions
// some instructions, like inc and dec, do not need to do this
//


//static void CreateInstrBreakpoint(llvm::BasicBlock *B, uint64_t pc) {
//  auto F = B->getParent();
//  auto M = F->getParent();
//
//  std::stringstream ss;
//  ss << "breakpoint_" << std::hex << pc;
//  auto instr_func_name = ss.str();
//
//  auto IFT = M->getFunction(instr_func_name);
//  if (!IFT) {
//
//    IFT = llvm::Function::Create(
//        LiftedFunctionType(), llvm::GlobalValue::ExternalLinkage,
//        instr_func_name, M);
//
//    IFT->addFnAttr(llvm::Attribute::OptimizeNone);
//    IFT->addFnAttr(llvm::Attribute::NoInline);
//
//    auto &C = M->getContext();
//    llvm::IRBuilder<> ir(llvm::BasicBlock::Create(C, "", IFT));
//    ir.CreateRetVoid();
//  }
//
//  auto state_ptr = &*F->arg_begin();
//  llvm::CallInst::Create(IFT, {state_ptr}, "", B);
//}

//static void AddRegStateTracer(llvm::BasicBlock *B) {
//  auto F = B->getParent();
//  auto M = F->getParent();
//  auto IFT = ArchGetOrCreateRegStateTracer(M);
//
//  auto state_ptr = &*F->arg_begin();
//  llvm::CallInst::Create(IFT, {state_ptr}, "", B);
//}

//
//struct DataSectionVar {
//  const DataSection *section;
//  llvm::StructType *opaque_type;
//  llvm::GlobalVariable *var;
//};
//
//// Insert all global data before we insert the CFG
//static bool InsertDataSections(const NativeModule *cfg_module) {
//  auto &globaldata = cfg_module->getData();
//
//  std::vector<DataSectionVar> gvars;
//
//  // pre-create references to all data sections
//  // as later we may have data references that are
//  // from one section into another
//
//  for (auto &dt : globaldata) {
//    std::stringstream ss;
//    ss << "data_" << std::hex << dt.getBase();
//    auto bufferName = ss.str();
//
//    LOG(INFO)
//        << "Inserting global data section named " << bufferName;
//
//    auto st_opaque = llvm::StructType::create(gModule->getContext());
//
//    // Used to be PrivateLinkage, but that emitted
//    // .objs that would not link with MSVC
//    auto g = new llvm::GlobalVariable(
//        *gModule, st_opaque, dt.isReadOnly(),
//        llvm::GlobalVariable::InternalLinkage,
//        nullptr, bufferName);
//    gvars.push_back({&dt, st_opaque, g});
//  }
//
//  // actually populate the data sections
//  for (auto &var : gvars) {
//
//    // Data we use to create LLVM values for this section
//    // secContents is the actual values we will be inserting
//    std::vector<llvm::Constant *> secContents;
//    // data_section_types is their types, which are needed to initialize
//    // the global variable
//    std::vector<llvm::Type *> data_section_types;
//
//    dataSectionToTypesContents(cfg_module, globaldata, *var.section,
//                               gModule, secContents, data_section_types, true);
//
//    // Fill in the opaqure structure with actual members.
//    var.opaque_type->setBody(data_section_types, true);
//
//    // Create an initializer list using the now filled in opaque
//    // structure type.
//    auto cst = llvm::ConstantStruct::get(var.opaque_type, secContents);
//
//    // Align to a 16-byte boundary; this is the max needed by aligned
//    // memory access instructions.
//    var.var->setAlignment(16);
//    var.var->setInitializer(cst);
//  }
//  return true;
//}
//
//
//
//static void InitExternalData(const NativeModule *cfg_module) {
//
//
//  for (auto data_ref : cfg_module->getExtDataRefs()) {
//    auto dsize = data_ref->getDataSize();
//    auto symname = data_ref->getSymbolName();
//    auto extType = llvm::ArrayType::get(
//        llvm::Type::getInt8Ty(*gContext), dsize);
//    auto gv = llvm::dyn_cast<llvm::GlobalValue>(
//        gModule->getOrInsertGlobal(symname, extType));
//
//    CHECK(gv != nullptr)
//        << "Could not make global value for external data symbol " << symname;
//
//    if (data_ref->isWeak()) {
//      gv->setLinkage(llvm::GlobalValue::ExternalWeakLinkage);
//    } else {
//      gv->setLinkage(llvm::GlobalValue::ExternalLinkage);
//    }
//
//    llvm::Triple triple(gModule->getTargetTriple());
//    if (llvm::Triple::Win32 == triple.getOS()) {
//      gv->setDLLStorageClass(llvm::GlobalValue::DLLImportStorageClass);
//    }
//  }
//}
//
//// Iterate over the list of external functions and insert them as
//// global functions.
//static void InitExternalCode(const NativeModule *cfg_module) {
//  for (const auto entry : cfg_module->name_to_extern_func) {
//    auto cfg_func = entry.second;
//
//    // Create the function if it is not already there.
//    auto func = gModule->getFunction(cfg_func->name);
//    if (func) {
//      continue;
//    }
//
//    auto func_type = llvm::FunctionType::get(
//        llvm::Type::getVoidTy(*gContext), true);
//
//    func = llvm::dyn_cast<llvm::Function>(
//        gModule->getOrInsertFunction(cfg_func->name, func_type));
//
//
//    // TODO(pag): Do calling convention and argument stuff here.
//
////    auto conv = e->getCallingConvention();
////    auto argCount = e->getNumArgs();
////    auto symName = e->getSymbolName();
////    auto funcSign = e->getFunctionSignature();
////
////    if (ExternalCodeRef::McsemaCall == conv) {
////       // normal mcsema function prototypes
////      F = llvm::dyn_cast<llvm::Function>(gModule->getOrInsertFunction(
////          ArchNameMcSemaCall(symName), LiftedFunctionType()));
////      ArchSetCallingConv(gModule, F);
////      F->setLinkage(llvm::GlobalValue::ExternalLinkage);
////      continue;
////    }
////
////    std::vector<llvm::Type *> arguments;
////    llvm::Type *returnType = nullptr;
////
////    // Create arguments.
////    const auto Arch = SystemArch(gModule);
////    const auto OS = SystemOS(gModule);
////    for (auto i = 0; i < argCount; i++) {
////      if (_X86_64_ == Arch) {
////        if (llvm::Triple::Win32 == OS) {
////          if (funcSign.c_str()[i] == 'F') {
////            arguments.push_back(llvm::Type::getDoubleTy(*gContext));
////          } else {
////            arguments.push_back(llvm::Type::getInt64Ty(*gContext));
////          }
////        } else if (llvm::Triple::Linux == OS) {
////          arguments.push_back(llvm::Type::getInt64Ty(*gContext));
////
////        } else {
////          LOG(FATAL)
////              << "Unknown OS Type!";
////        }
////      } else {
////        arguments.push_back(llvm::Type::getInt32Ty(*gContext));
////      }
////    }
////
////    // Create function type
////    switch (e->getReturnType()) {
////      case ExternalCodeRef::NoReturn:
////      case ExternalCodeRef::VoidTy:
////        returnType = llvm::Type::getVoidTy(*gContext);
////        break;
////
////      case ExternalCodeRef::Unknown:
////      case ExternalCodeRef::IntTy:
////        if (cfg_module->is64Bit()) {
////          returnType = llvm::Type::getInt64Ty(*gContext);
////        } else {
////          returnType = llvm::Type::getInt32Ty(*gContext);
////        }
////        break;
////
////      default:
////        LOG(FATAL)
////            << "Encountered an unknown return type while translating function";
////    }
////
////    auto FTy = llvm::FunctionType::get(returnType, arguments, false);
////    if (e->isWeak()) {
////      F = llvm::Function::Create(FTy, llvm::GlobalValue::ExternalWeakLinkage,
////                                 symName, gModule);
////    } else {
////      F = llvm::Function::Create(FTy, llvm::GlobalValue::ExternalLinkage,
////                                 symName, gModule);
////    }
////
////    if (e->getReturnType() == ExternalCodeRef::NoReturn) {
////      F->setDoesNotReturn();
////    }
////
////    // Set calling convention
////    if (cfg_module->is64Bit()) {
////      ArchSetCallingConv(gModule, F);
////    } else {
////      F->setCallingConv(getLLVMCC(conv));
////    }
//  }
//}
}  // namespace

bool LiftCodeIntoModule(const NativeModule *cfg_module) {
  DeclareExternals(cfg_module);
  DeclareLiftedFunctions(cfg_module);

  // Segments are inserted after the lifted function declarations are added
  // so that cross-references to lifted code are handled.
  AddDataSegments(cfg_module);

  if (!DefineLiftedFunctions(cfg_module)) {
    return false;
  } else {
    OptimizeModule();
    return true;
  }
}

}  // namespace mcsema
