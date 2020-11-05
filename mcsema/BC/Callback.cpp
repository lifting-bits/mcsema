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

#include "mcsema/BC/Callback.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wswitch-enum"
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#pragma clang diagnostic pop

#include <anvill/Decl.h>
#include <anvill/Lift.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Annotate.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>

#include <sstream>
#include <string>
#include <vector>

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Legacy.h"
#include "mcsema/BC/Segment.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

DECLARE_string(pc_annotation);

DEFINE_bool(explicit_args, false,
            "Should arguments be explicitly passed to external functions. "
            "This can be good for static analysis and symbolic execution, "
            "but in practice it reduces the portability of the resulting "
            "bitcode, especially where floating point argument and return "
            "values are concerned.");

DEFINE_uint32(
    explicit_args_count, 8,
    "Number of explicit (integer) arguments to pass to an unknown "
    "function, or to accept from an unknown function. This value is "
    "used when calling external functions for which no type "
    "information is known, or who take a variable number of arguments.");

DEFINE_uint32(explicit_args_stack_size, 4096 * 256 /* 1 MiB */,
              "Size of the stack of the emulated program when the program "
              "is lifted using --explicit_args.");

DEFINE_uint32(explicit_args_tls_size, 4 * 4096,
              "Number of bytes of thread local storage");

DEFINE_bool(use_native_thread_base, false,
            "Try to find and use the native thread base pointer.");

DECLARE_bool(stack_protector);

namespace mcsema {
namespace {

static llvm::Function *GetAttachCallFunc(void) {
  static llvm::Function *handler = nullptr;
  if (!handler) {
    auto void_type = llvm::Type::getVoidTy(*gContext);
    auto callback_type = llvm::FunctionType::get(void_type, false);
    handler = llvm::Function::Create(callback_type,
                                     llvm::GlobalValue::ExternalLinkage,
                                     "__mcsema_attach_call", gModule.get());
    handler->addFnAttr(llvm::Attribute::NoInline);
    remill::Annotate<remill::McSemaHelper>(handler);
  }
  return handler;
}

static llvm::Function *DetachCallValueFunc(void) {
  static llvm::Function *handler = nullptr;
  if (!handler) {
    handler = gModule->getFunction("__remill_function_call");
  }
  return handler;
}

// Get a callback function for an internal function.
static llvm::Function *
ImplementNativeToLiftedCallback(const NativeObject *cfg_func,
                                const std::string &callback_name) {

  // If the native name of the function doesn't yet exist then add it in.
  auto func = gModule->getFunction(cfg_func->lifted_name);
  CHECK(func != nullptr) << "Cannot find lifted function "
                         << cfg_func->lifted_name;

  auto attach_func = GetAttachCallFunc();

  // Generate inline assembly that can be used the go from native machine
  // state into lifted code. The inline assembly saves a pointer to the lifted
  // function and the original lifted function's address (from the CFG), and
  // then jumps into `__mcsema_attach_call`, which does the low-level
  // marshaling of native register state into the `State` structure.
  std::stringstream asm_str;
  switch (gArch->arch_name) {
    case remill::kArchInvalid:
      LOG(FATAL) << "Cannot generate native-to-lifted entrypoint thunk for "
                 << "unknown architecture.";
      break;
    case remill::kArchAMD64:
    case remill::kArchAMD64_AVX:
    case remill::kArchAMD64_AVX512:
      asm_str << "pushq $0;";
      if (static_cast<uint32_t>(cfg_func->ea) == cfg_func->ea) {
        asm_str << "pushq $$0x" << std::hex << cfg_func->ea << ";";
      } else {
        asm_str << "pushq %rax;"
                << "movq $$0x" << std::hex << cfg_func->ea << ", %rax;"
                << "xchgq (%rsp), %rax;";
      }
      asm_str << "jmpq *$1;";
      break;

    case remill::kArchX86:
    case remill::kArchX86_AVX:
    case remill::kArchX86_AVX512:
      asm_str << "pushl $0;"
              << "pushl $$0x" << std::hex << cfg_func->ea << ";"
              << "jmpl *$1;";
      break;

    case remill::kArchAArch64LittleEndian:
      LOG(ERROR) << "TODO: Create a native-to-lifted callback for the "
                 << GetArchName(gArch->arch_name) << " instruction set.";
      asm_str << "nop;";
      break;

    default:
      LOG(FATAL) << "Cannot create native-to-lifted callback for the "
                 << GetArchName(gArch->arch_name) << " instruction set.";
      break;
  }

  auto void_type = llvm::Type::getVoidTy(*gContext);

  // Create the callback function that calls the inline assembly.
  auto callback_type = llvm::FunctionType::get(void_type, false);
  auto callback_func = gModule->getFunction(callback_name);
  if (!callback_func) {
    callback_func = llvm::Function::Create(
        callback_type,
        llvm::GlobalValue::InternalLinkage,  // Tentative linkage.
        callback_name, gModule.get());
  }
  callback_func->setVisibility(llvm::GlobalValue::DefaultVisibility);
  callback_func->addFnAttr(llvm::Attribute::Naked);
  callback_func->addFnAttr(llvm::Attribute::NoInline);
  callback_func->addFnAttr(llvm::Attribute::NoBuiltin);

  // Create the inline assembly. We use memory operands (
  std::vector<llvm::Type *> asm_arg_types;
  std::vector<llvm::Value *> asm_args;
  asm_arg_types.push_back(llvm::PointerType::get(func->getType(), 0));
  asm_arg_types.push_back(llvm::PointerType::get(attach_func->getType(), 0));
  auto asm_func_type = llvm::FunctionType::get(void_type, asm_arg_types, false);
  auto asm_func = llvm::InlineAsm::get(asm_func_type, asm_str.str(),
                                       "*m,*m,~{dirflag},~{fpsr},~{flags}",
                                       true /* hasSideEffects */);

  // Make an initializer function that first calls `__mcsema_early_init`,
  // then calls the lifted bitcode function. When lifting C++ code, often
  // you will get weak functions, e.g. `std::string::data()`, implemented
  // in the main binary, and depended on by libraries that are loaded and
  // initialized before the main binary's constructors. This results in
  // a re-entrancy bug, where the dynamic loader will link a native library's
  // use of a C++ symbol against an exported version of it in the lifted
  // binary, and then lifted code gets called too early. Normally, the lazy
  // initialization of cross-references happens in `__mcsema_constructor`,
  // but we need to also have it happen here just in case lifted code gets
  // called before `__mcsema_constructor` is invoked.
  std::stringstream func_wrapper_name;
  func_wrapper_name << callback_name;
  func_wrapper_name << "_wrapper";
  auto func_wrapper = llvm::Function::Create(
      func->getFunctionType(), llvm::GlobalValue::InternalLinkage,
      func_wrapper_name.str(), gModule.get());
  auto arg_it = func_wrapper->arg_begin();

  llvm::IRBuilder<> ir(llvm::BasicBlock::Create(*gContext, "", func_wrapper));
  llvm::Value *func_args[3];
  func_args[0] = &*arg_it++;
  func_args[1] = &*arg_it++;
  func_args[2] = &*arg_it++;

  ir.CreateCall(GetOrCreateMcSemaInitializer());
  auto call = ir.CreateCall(func, func_args);
  call->setTailCall(true);
  ir.CreateRet(call);

  // Back to the asm attach callback thunk...
  ir.SetInsertPoint(llvm::BasicBlock::Create(*gContext, "", callback_func));

  // It's easier to deal with memory references in inline assembly in static
  // and relocatable binaries, but the cost is that we have to produce these
  // otherwise useless global variables.
  asm_args.push_back(new llvm::GlobalVariable(
      *gModule, func_wrapper->getType(), true /* isConstant */,
      llvm::GlobalValue::InternalLinkage, func_wrapper));

  static llvm::GlobalVariable *attach_func_ptr = nullptr;
  if (!attach_func_ptr) {
    attach_func_ptr = new llvm::GlobalVariable(
        *gModule, attach_func->getType(), true,
        llvm::GlobalValue::InternalLinkage, attach_func);
  }

  asm_args.push_back(attach_func_ptr);

  ir.CreateCall(asm_func, asm_args);

  if (auto ret_type = callback_func->getReturnType(); ret_type->isVoidTy()) {
    ir.CreateRetVoid();
  } else {
    ir.CreateRet(llvm::UndefValue::get(ret_type));
  }

  if (!FLAGS_pc_annotation.empty()) {
    legacy::AnnotateInsts(callback_func, cfg_func->ea);
  }

  if (cfg_func->is_exported) {
    callback_func->setLinkage(llvm::GlobalValue::ExternalLinkage);
    callback_func->setDLLStorageClass(llvm::GlobalValue::DLLExportStorageClass);
  }

  return callback_func;
}

// Create a stack and a variable that tracks the stack pointer.
static llvm::Constant *InitialStackPointerValue(void) {
  unsigned min_frame_size = 512u;
  const auto num_bytes =
      std::max(FLAGS_explicit_args_stack_size, 4096u + min_frame_size);
  auto i8_type = llvm::Type::getInt8Ty(*gContext);
  auto stack_type = llvm::ArrayType::get(i8_type, num_bytes);

  static llvm::Constant *stack = nullptr;
  if (!stack) {
    auto stack_var = new llvm::GlobalVariable(
        *gModule, stack_type, false, llvm::GlobalValue::InternalLinkage,
        llvm::ConstantAggregateZero::get(stack_type), "__mcsema_stack", nullptr,
        llvm::GlobalValue::InitialExecTLSModel);
    stack = stack_var;

    if (stack_var->getType()->getAddressSpace()) {
      stack = llvm::ConstantExpr::getAddrSpaceCast(
          stack_var, llvm::PointerType::get(stack_type, 0));
    }
  }

  const auto i32_ty = llvm::Type::getInt32Ty(*gContext);
  llvm::Constant *indexes[2];
  indexes[0] = llvm::ConstantInt::get(i32_ty, 0);
  indexes[1] = llvm::ConstantInt::get(i32_ty, num_bytes - min_frame_size);

#if LLVM_VERSION_NUMBER <= LLVM_VERSION(3, 6)
  auto gep = llvm::ConstantExpr::getInBoundsGetElementPtr(stack, indexes);
#else
  auto gep =
      llvm::ConstantExpr::getInBoundsGetElementPtr(nullptr, stack, indexes);
#endif
  auto ival = llvm::ConstantExpr::getPtrToInt(gep, gWordType);

  if (gArch->IsLinux() || gArch->IsMacOS() || gArch->IsSolaris()) {

    // SysV ABI requires that `esp + 4` is 16-byte aligned.
    if (gArch->IsX86()) {
      ival = llvm::ConstantExpr::getAnd(
          ival, llvm::ConstantInt::get(gWordType, ~15u));
      ival = llvm::ConstantExpr::getSub(ival,
                                        llvm::ConstantInt::get(gWordType, 4u));

    // `rsp` is 16-byte aligned on entry to a function.
    } else if (gArch->IsAMD64()) {
      ival = llvm::ConstantExpr::getAnd(
          ival, llvm::ConstantInt::get(gWordType, ~15ull));
    }
  }

  return ival;
}

static llvm::InlineAsm *ThreadPointerAsm(void) {
  auto fty = llvm::FunctionType::get(gWordType, false);
  switch (gArch->arch_name) {
    case remill::kArchX86:
    case remill::kArchX86_AVX:
    case remill::kArchX86_AVX512: {
      switch (gArch->os_name) {
        case remill::kOSLinux:
          return llvm::InlineAsm::get(fty, "mov %gs:0, $0", "=r,~{memory}", false,
                                      false, llvm::InlineAsm::AD_ATT);

        case remill::kOSmacOS:
          LOG(FATAL) << "32-bit macOS targets are not supported";
          break;

        case remill::kOSWindows:
          return llvm::InlineAsm::get(fty, "mov %fs:0, $0", "=r,~{memory}", false,
                                      false, llvm::InlineAsm::AD_ATT);

        default: break;
      }
      break;
    }

    case remill::kArchAMD64:
    case remill::kArchAMD64_AVX:
    case remill::kArchAMD64_AVX512: {
      switch (gArch->os_name) {
        case remill::kOSLinux:
          return llvm::InlineAsm::get(fty, "mov %fs:0, $0", "=r,~{memory}",
                                      false, false, llvm::InlineAsm::AD_ATT);

        case remill::kOSmacOS:
          LOG(FATAL) << "32-bit macOS targets are not supported";
          break;

        case remill::kOSWindows:
          return llvm::InlineAsm::get(fty, "mov %gs:0, $0", "=r,~{memory}",
                                      false, false, llvm::InlineAsm::AD_ATT);

        default: break;
      }
      break;
    }
    case remill::kArchAArch64LittleEndian:
      return llvm::InlineAsm::get(fty, "mov $0, %TPIDR_EL0", "=r,~{memory}",
                                  false, false, llvm::InlineAsm::AD_ATT);

    case remill::kArchSparc32:
    case remill::kArchSparc64:
      return llvm::InlineAsm::get(fty, "mov $0, %g7", "=r,~{memory}", false,
                                  false, llvm::InlineAsm::AD_ATT);

    default:
      break;
  }

  LOG(FATAL) << "Cannot determine inline assembly for accessing thread base";
}

static const char *ThreadPointerNameX86(void) {
  switch (gArch->os_name) {
    case remill::kOSLinux: return "GS_BASE";
    case remill::kOSWindows: return "FS_BASE";
    default: return nullptr;
  }
}

static const char *ThreadPointerNameAMD64(void) {
  switch (gArch->os_name) {
    case remill::kOSLinux: return "FS_BASE";
    case remill::kOSWindows: return "GS_BASE";
    default: return nullptr;
  }
}

static const char *ThreadPointerName(void) {
  const char *tp_name = nullptr;
  switch (gArch->arch_name) {
    case remill::kArchAArch64LittleEndian: return "TPIDR_EL0";

    case remill::kArchX86:
    case remill::kArchX86_AVX:
    case remill::kArchX86_AVX512: tp_name = ThreadPointerNameX86(); break;

    case remill::kArchAMD64:
    case remill::kArchAMD64_AVX:
    case remill::kArchAMD64_AVX512: tp_name = ThreadPointerNameAMD64(); break;

    default: break;
  }

  LOG_IF(ERROR, !tp_name) << "Can't get thread pointer name for architecture "
                          << remill::GetArchName(gArch->arch_name) << " and OS "
                          << remill::GetOSName(gArch->os_name);
  return tp_name;
}

// Create an array of data for holding thread-local storage.
static llvm::Value *InitialThreadLocalStorage(llvm::IRBuilder<> &ir) {
  if (FLAGS_use_native_thread_base) {
    return ir.CreateCall(ThreadPointerAsm());
  }

  // Add some TLS pages.
  llvm::ArrayType *tls_type = llvm::ArrayType::get(
      gWordType, FLAGS_explicit_args_tls_size / (gArch->address_size / 8));

  auto tls_var = new llvm::GlobalVariable(
      *gModule, tls_type, false, llvm::GlobalValue::InternalLinkage,
      llvm::Constant::getNullValue(tls_type), "__mcsema_tls", nullptr,
      llvm::GlobalValue::InitialExecTLSModel);

  llvm::Constant *tls = tls_var;
  if (tls_var->getType()->getAddressSpace()) {
    tls = llvm::ConstantExpr::getAddrSpaceCast(
        tls_var, llvm::PointerType::get(tls_type, 0));
  }

  const auto i32_ty = llvm::Type::getInt32Ty(*gContext);
  llvm::Constant *indexes[2];
  indexes[0] = llvm::ConstantInt::get(i32_ty, 0);
  indexes[1] = indexes[0];

#if LLVM_VERSION_NUMBER <= LLVM_VERSION(3, 6)
  tls = llvm::ConstantExpr::getInBoundsGetElementPtr(tls, indexes);
#else
  tls = llvm::ConstantExpr::getInBoundsGetElementPtr(nullptr, tls, indexes);
#endif

  tls = llvm::ConstantExpr::getPtrToInt(tls, gWordType);
  return tls;
}

// NOTE(lukas): We don't need to annotate, it will always be inlined.
static llvm::Function *CreateVerifyRegState(void) {
  auto reg_state = GetStatePointer();
  auto *func_type = llvm::FunctionType::get(reg_state->getType(), false);
  auto new_func =
      gModule->getOrInsertFunction("__mcsema_init_reg_state", func_type);
  auto func =
      llvm::dyn_cast<llvm::Function>(new_func IF_LLVM_GTE_900(.getCallee()));

  CHECK(func != nullptr)
      << "Could not get or create function '__mcsema_init_reg_state'";

  const auto sp_name = gArch->StackPointerRegisterName();
  auto sp_reg = gArch->RegisterByName(sp_name);

  auto entry_block = llvm::BasicBlock::Create(*gContext, "entry", func);
  auto is_null_block = llvm::BasicBlock::Create(*gContext, "is_null", func);
  auto end_block = llvm::BasicBlock::Create(*gContext, "end", func);
  llvm::IRBuilder<> ir(entry_block);

  // Need to find out where stack pointer is and known information is
  // byte offset in state structure
  //  auto byte_ty = llvm::Type::getInt8PtrTy(*gContext);
  unsigned ptr_size = static_cast<unsigned>(gArch->address_size);
  auto reg_ptr_ty = llvm::PointerType::getIntNPtrTy(*gContext, ptr_size);

  //TODO(lukas): remove after abi_libraries patch gets merged into master
  auto GetConstantInt = [&](unsigned size, uint64_t value) {
    return llvm::ConstantInt::get(llvm::Type::getIntNTy(*gContext, size),
                                  value);
  };

  //  auto casted_reg_state = ir.CreateBitCast(reg_state, byte_ty);
  auto rsp = sp_reg->AddressOf(reg_state, entry_block);
  auto casted_rsp = ir.CreateBitCast(rsp, reg_ptr_ty);
  auto rsp_val =
      ir.CreateLoad(casted_rsp, llvm::Type::getIntNTy(*gContext, ptr_size));
  auto comparison = ir.CreateICmpEQ(rsp_val, GetConstantInt(ptr_size, 0));
  ir.CreateCondBr(comparison, is_null_block, end_block);

  // Stack pointer is pointing at nothing, so we need to set it up
  ir.SetInsertPoint(is_null_block);
  ir.CreateStore(InitialStackPointerValue(), casted_rsp);

  // Store the address of `__mcsema_tls` into the TLS register.
  if (auto tp_name = ThreadPointerName(); tp_name) {
    if (auto tp_reg = gArch->RegisterByName(tp_name); tp_reg) {
      ir.CreateStore(InitialThreadLocalStorage(ir),
                     tp_reg->AddressOf(reg_state, is_null_block));
    }
  }

  ir.SetInsertPoint(is_null_block);

  // Call the `__mcsema_early_init` function to make sure all lazy cross-
  // reference initializers have been installed before any lifted bitcode
  // is executed.
  ir.CreateCall(GetOrCreateMcSemaInitializer());

  ir.CreateBr(end_block);

  // Last block just returns void
  ir.SetInsertPoint(end_block);
  ir.CreateRet(reg_state);

  return func;
}

// TODO(lukas): VerifyRegState is probably not the best name.
//              Maybe VerifyStackPointer?
//              Opened to suggestions.

// Because of possible parallelism, both global stack and state must be
// thread_local. However after new thread is created, its stack and state
// are initialized to default values.
// Which means that state is zero initialized
// This function verifies that the stack pointer points to some location
// and if not then sets it up to point into stack with default offset
static llvm::Function *GetVerifyRegState(void) {
  static llvm::Function *func = nullptr;
  if (!func) {
    func = CreateVerifyRegState();
  }
  return func;
}

// Implements a stub for an externally defined function in such a way that
// the external is explicitly called, and arguments from the modeled CPU
// state are passed into the external.
static llvm::Function *
ImplementExplicitArgsEntryPoint(const NativeFunction *cfg_func,
                                const std::string &name) {

  auto func = gModule->getFunction(name);
  if (!func) {
    auto num_args = FLAGS_explicit_args_count;

    // Get correct return type -> i32 for main
    llvm::Type *ret_type = gWordType;
    if (name == "main" || name == "_main") {
      num_args = 3;
      ret_type = llvm::Type::getInt32Ty(*gContext);
    }

    LOG(INFO) << "Generating explicit argument entrypoint function for " << name
              << ", calling into " << cfg_func->lifted_name;

    std::vector<llvm::Type *> arg_types(num_args, gWordType);

    auto func_type = llvm::FunctionType::get(ret_type, arg_types, false);
    func = llvm::Function::Create(func_type, llvm::GlobalValue::InternalLinkage,
                                  name, gModule.get());
    DCHECK_EQ(func->getName().str(), name);
  }

  if (!func->isDeclaration()) {
    return func;
  }

  auto maybe_decl = anvill::FunctionDecl::Create(*func, gArch);
  if (remill::IsError(maybe_decl)) {
    LOG(FATAL) << remill::GetErrorString(maybe_decl);
  }

  auto &decl = remill::GetReference(maybe_decl);
  decl.address = cfg_func->ea;

  // We have the decompiled function, or at least, a prefix of it,
  // so we'll invent a state structure and a stack frame and we'll
  // call the lifted function with that. The lifted function will
  // get inlined into this function.

  auto block = llvm::BasicBlock::Create(*gContext, "", func);
  llvm::IRBuilder<> ir(block);

  // Invent a memory pointer.
  const auto mem_ptr_type = gArch->MemoryPointerType();
  llvm::Value *mem_ptr = llvm::Constant::getNullValue(mem_ptr_type);

  const auto state_ptr = ir.CreateCall(GetVerifyRegState());

  const auto pc = llvm::ConstantInt::get(gWordType, cfg_func->ea);

  static remill::IntrinsicTable intrinsics(gModule);

  // Store the function parameters either into the state struct
  // or into memory (likely the stack).
  auto arg_index = 0u;
  for (auto &arg : func->args()) {
    const auto &param_decl = decl.params[arg_index++];
    mem_ptr = anvill::StoreNativeValue(&arg, param_decl, intrinsics, block,
                                       state_ptr, mem_ptr);
  }

  llvm::Value *lifted_func_args[remill::kNumBlockArgs] = {};
  lifted_func_args[remill::kStatePointerArgNum] = state_ptr;
  lifted_func_args[remill::kMemoryPointerArgNum] = mem_ptr;
  lifted_func_args[remill::kPCArgNum] = pc;
  mem_ptr = ir.CreateCall(cfg_func->lifted_function, lifted_func_args);

  llvm::Value *ret_val = nullptr;

  if (decl.returns.size() == 1) {
    ret_val = anvill::LoadLiftedValue(decl.returns.front(), intrinsics, block,
                                      state_ptr, mem_ptr);
    ir.SetInsertPoint(block);

  } else if (1 < decl.returns.size()) {
    ret_val = llvm::UndefValue::get(func->getReturnType());
    auto index = 0u;
    for (auto &ret_decl : decl.returns) {
      auto partial_ret_val = anvill::LoadLiftedValue(ret_decl, intrinsics,
                                                     block, state_ptr, mem_ptr);
      ir.SetInsertPoint(block);
      unsigned indexes[] = {index};
      ret_val = ir.CreateInsertValue(ret_val, partial_ret_val, indexes);
      index += 1;
    }
  }

  if (ret_val) {
    ir.CreateRet(ret_val);
  } else {
    ir.CreateRetVoid();
  }

  return func;
}

static llvm::Function *GetOrCreateCallback(const NativeFunction *cfg_func,
                                           const std::string &callback_name) {
  if (cfg_func->function) {
    return cfg_func->function;
  }

  CHECK_NOTNULL(cfg_func->lifted_function);

  if (FLAGS_explicit_args) {
    cfg_func->function =
        ImplementExplicitArgsEntryPoint(cfg_func, callback_name);
  } else {
    cfg_func->function =
        ImplementNativeToLiftedCallback(cfg_func, callback_name);
  }

  return cfg_func->function;
}

// Adapt a variadic function type to have the same signature, but have additional
// explicit "padding" arguments so that the function has at least `num_args`
// parameters.
static llvm::FunctionType *AdaptFunctionType(llvm::FunctionType *type,
                                             unsigned num_args) {
  std::vector<llvm::Type *> param_types(
      std::max(num_args, type->getNumParams()), gWordType);

  auto i = 0u;
  for (auto param_type : type->params()) {
    param_types[i++] = param_type;
  }

  return llvm::FunctionType::get(type->getReturnType(), param_types, false);
}

// If `va_func` is not variadic, then this returns `va_func`, otherwise
// `va_func` is wrapped with a function that may take in additional explicit
// integer arguments, and then will pass those to `va_func`.
static llvm::Function *WrapVarArgsFunction(llvm::Function *va_func) {
  if (!va_func->isVarArg()) {
    return va_func;
  }

  auto func_type =
      AdaptFunctionType(va_func->getFunctionType(), FLAGS_explicit_args_count);

  auto wrapper_function =
      llvm::Function::Create(func_type, llvm::GlobalValue::InternalLinkage,
                             va_func->getName() + "_novarargs", gModule.get());

  std::vector<llvm::Value *> params;
  for (auto &arg : wrapper_function->args()) {
    params.push_back(&arg);
  }

  llvm::IRBuilder<> ir(
      llvm::BasicBlock::Create(*gContext, "", wrapper_function));
  auto call = ir.CreateCall(va_func, params);
  if (func_type->getReturnType()->isVoidTy()) {
    ir.CreateRetVoid();
  } else {
    ir.CreateRet(call);
  }

  wrapper_function->setCallingConv(va_func->getCallingConv());

  return wrapper_function;
}

// Implements a stub for an externally defined function in such a way that,
// when executed, this stub redirects control flow into the actual external
// function.
static void ImplementLiftedToNativeCallback(llvm::Function *callback_func,
                                            llvm::Function *extern_func) {

  callback_func->addFnAttr(llvm::Attribute::NoInline);

  auto block = llvm::BasicBlock::Create(*gContext, "", callback_func);

  // The third argument of lifted functions (including things like
  // `__remill_function_call`) is the program counter. Make sure that
  // the "real" address of the external is passed in as that third argument
  // because it's likely that whatever was in the CFG makes no sense
  // in the lifted code.
  auto args = remill::LiftedFunctionArgs(block);
  args[remill::kPCArgNum] =
      llvm::ConstantExpr::getPtrToInt(extern_func, gWordType);

  llvm::IRBuilder<> ir(block);
  auto handler_call = ir.CreateCall(DetachCallValueFunc(), args);
  ir.CreateRet(handler_call);
}

// Implements a stub for an externally defined function in such a way that
// the external is explicitly called, and arguments from the modeled CPU
// state are passed into the external.
static void ImplementExplicitArgsExitPoint(llvm::Function *callback_func,
                                           llvm::Function *extern_func) {

  extern_func = WrapVarArgsFunction(extern_func);
  auto maybe_decl = anvill::FunctionDecl::Create(*extern_func, gArch);
  if (remill::IsError(maybe_decl)) {
    LOG(FATAL) << remill::GetErrorString(maybe_decl);
  }

  const auto &decl = remill::GetReference(maybe_decl);

  remill::CloneBlockFunctionInto(callback_func);
  auto block = &(callback_func->getEntryBlock());

  auto pc = remill::NthArgument(callback_func, remill::kPCArgNum);
  auto mem_ptr =
      remill::NthArgument(callback_func, remill::kMemoryPointerArgNum);
  auto state_ptr =
      remill::NthArgument(callback_func, remill::kStatePointerArgNum);

  llvm::IRBuilder<> ir(block);

  llvm::Value *next_pc_ref = nullptr;
  next_pc_ref = ir.CreateAlloca(
      gWordType, llvm::Constant::getNullValue(gWordType), "next_pc");
  ir.CreateStore(pc, next_pc_ref);

  const auto mem_ptr_ref =
      ir.CreateAlloca(mem_ptr->getType(), nullptr, "MEMORY");
  const auto pc_ref = ir.CreateAlloca(gWordType, nullptr, "PC");
  ir.CreateStore(mem_ptr, mem_ptr_ref);
  ir.CreateStore(pc, pc_ref);

  // Optimization can sometimes result in memory accesses being reordered w.r.t.
  // external calls if they are inlined, so we want to prevent their inlining.
  callback_func->removeFnAttr(llvm::Attribute::InlineHint);
  callback_func->removeFnAttr(llvm::Attribute::AlwaysInline);
  callback_func->addFnAttr(llvm::Attribute::NoInline);

  if (FLAGS_stack_protector) {
    callback_func->addFnAttr(llvm::Attribute::StackProtectReq);
  }

  callback_func->setLinkage(llvm::GlobalValue::InternalLinkage);

  remill::IntrinsicTable intrinsics(gModule);
  const auto new_mem_ptr =
      decl.CallFromLiftedBlock(extern_func->getName().str(), intrinsics, block,
                               state_ptr, mem_ptr, true);

  ir.CreateRet(new_mem_ptr);
}

}  // namespace

llvm::Constant *NativeFunction::Pointer(void) const {
  if (function) {
    return function;
  }

  if (name.empty()) {
    std::stringstream ss;
    ss << "callback_" << lifted_name;
    name = ss.str();
  }

  module->AddNameToAddress(name, ea);
  if (decl) {
    decl->DeclareInModule(name, *gModule);
  }

  function = GetOrCreateCallback(this, name);

  // Always set as external until we've lifted the data segments.
  function->setLinkage(llvm::GlobalValue::ExternalLinkage);

  function->removeFnAttr(llvm::Attribute::InlineHint);
  function->removeFnAttr(llvm::Attribute::AlwaysInline);
  function->removeFnAttr(llvm::Attribute::ReadNone);
  function->removeFnAttr(llvm::Attribute::ReadOnly);
  function->removeFnAttr(llvm::Attribute::ArgMemOnly);

  function->addFnAttr(llvm::Attribute::NoInline);
  function->addFnAttr(llvm::Attribute::NoBuiltin);

  return function;
}

llvm::Constant *NativeFunction::Address(void) const {
  return llvm::ConstantExpr::getPtrToInt(Pointer(), gWordType);
}

// Get a callback function for an external function that can be referenced by
// internal code.
llvm::Function *GetLiftedToNativeExitPoint(const NativeFunction *cfg_func) {

  if (cfg_func->callable_lifted_function) {
    return cfg_func->callable_lifted_function;
  }

  // Stub that will marshal lifted state into the native state.
  const auto callback_func = llvm::Function::Create(
      gArch->LiftedFunctionType(), llvm::GlobalValue::InternalLinkage,
      cfg_func->lifted_name, gModule.get());

  cfg_func->callable_lifted_function = callback_func;

  const auto extern_func = llvm::dyn_cast<llvm::Function>(cfg_func->Pointer());

  // Pass through the memory and state pointers, and pass the destination
  // (native external function address) as the PC argument.
  if (FLAGS_explicit_args) {
    ImplementExplicitArgsExitPoint(callback_func, extern_func);

  // We are going from lifted to native code. We don't need an assembly stub
  // because `__remill_function_call` already does the right thing.
  } else {
    ImplementLiftedToNativeCallback(callback_func, extern_func);
  }

  if (cfg_func->lifted_function && !FLAGS_pc_annotation.empty()) {
    legacy::AnnotateInsts(cfg_func->lifted_function, cfg_func->ea);
  }

  return callback_func;
}

// Get a function that goes from the current lifted state into native state,
// where we don't know where the native destination actually is.
llvm::Function *GetLiftedToNativeExitPoint(ExitPointKind kind) {

  if (!FLAGS_explicit_args) {
    switch (kind) {
      case kExitPointJump: return gModule->getFunction("__remill_jump");
      case kExitPointFunctionCall:
        return gModule->getFunction("__remill_function_call");
    }
  }

  // Using explicit args mode, so get a callback function that casts the
  // program counter into a function pointer and then calls it.
  static llvm::Function *callback_func = nullptr;
  if (callback_func) {
    return callback_func;
  }

  std::vector<llvm::Type *> arg_types;
  arg_types.insert(arg_types.end(), FLAGS_explicit_args_count, gWordType);

  // We'll create and destroy this function a few times just for the sake of
  // being able to get/use an anvill::FunctionDecl, and later, to get a function
  // pointer of the right type.
  auto func = llvm::Function::Create(
      llvm::FunctionType::get(gWordType, arg_types, false),
      llvm::GlobalValue::InternalLinkage, "__mcsema_do_detach_call_value",
      gModule.get());

  auto maybe_decl = anvill::FunctionDecl::Create(*func, gArch);
  func->eraseFromParent();

  if (remill::IsError(maybe_decl)) {
    LOG(FATAL) << "Unable to create exit point: "
               << remill::GetErrorString(maybe_decl);
    return nullptr;
  }

  const auto &decl = remill::GetReference(maybe_decl);
  func = decl.DeclareInModule("__mcsema_do_detach_call_value", *gModule, true);
  CHECK_NOTNULL(func);

  // Stub that will marshal lifted state into the native state.
  callback_func = llvm::Function::Create(
      gArch->LiftedFunctionType(), llvm::GlobalValue::PrivateLinkage,
      "__mcsema_detach_call_value", gModule.get());

  remill::CloneBlockFunctionInto(callback_func);
  auto block = &(callback_func->getEntryBlock());

  auto pc = remill::NthArgument(callback_func, remill::kPCArgNum);
  auto mem_ptr =
      remill::NthArgument(callback_func, remill::kMemoryPointerArgNum);
  auto state_ptr =
      remill::NthArgument(callback_func, remill::kStatePointerArgNum);

  llvm::IRBuilder<> ir(block);
  auto pc_as_func_ptr = ir.CreateIntToPtr(pc, func->getType());

  remill::IntrinsicTable intrinsics(gModule);
  const auto new_mem_ptr =
      decl.CallFromLiftedBlock("__mcsema_do_detach_call_value", intrinsics,
                               block, state_ptr, mem_ptr, true);

  func->replaceAllUsesWith(pc_as_func_ptr);
  func->eraseFromParent();

  ir.CreateRet(new_mem_ptr);

  remill::Annotate<remill::McSemaHelper>(callback_func);

  callback_func->removeFnAttr(llvm::Attribute::NoInline);
  callback_func->addFnAttr(llvm::Attribute::InlineHint);
  callback_func->addFnAttr(llvm::Attribute::AlwaysInline);
  callback_func->addFnAttr(llvm::Attribute::NoUnwind);

  return callback_func;
}

}  // namespace mcsema
