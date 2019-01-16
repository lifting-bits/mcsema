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
#include <gflags/gflags.h>

#include <sstream>
#include <string>
#include <vector>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"

#include "mcsema/Arch/ABI.h"
#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Callback.h"
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

DEFINE_uint64(explicit_args_count, 8,
              "Number of explicit (integer) arguments to pass to an unknown "
              "function, or to accept from an unknown function. This value is "
              "used when ");

DEFINE_uint64(explicit_args_stack_size, 4096 * 256  /* 1 MiB */,
              "Size of the stack of the emulated program when the program "
              "is lifted using --explicit_args.");

DECLARE_bool(stack_protector);

namespace mcsema {
namespace {

static llvm::Function *GetAttachCallFunc(void) {
  static llvm::Function *handler = nullptr;
  if (!handler) {
    auto void_type = llvm::Type::getVoidTy(*gContext);
    auto callback_type = llvm::FunctionType::get(void_type, false);
    handler = llvm::Function::Create(
        callback_type, llvm::GlobalValue::ExternalLinkage,
        "__mcsema_attach_call", gModule);
    handler->addFnAttr(llvm::Attribute::NoInline);
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
static llvm::Function *ImplementNativeToLiftedCallback(
    const NativeObject *cfg_func, const std::string &callback_name) {

  // If the native name of the function doesn't yet exist then add it in.
  auto func = gModule->getFunction(cfg_func->lifted_name);
  CHECK(func != nullptr)
      << "Cannot find lifted function " << cfg_func->lifted_name;

  auto attach_func = GetAttachCallFunc();

  // Generate inline assembly that can be used the go from native machine
  // state into lifted code. The inline assembly saves a pointer to the lifted
  // function and the original lifted function's address (from the CFG), and
  // then jumps into `__mcsema_attach_call`, which does the low-level
  // marshaling of native register state into the `State` structure.
  std::stringstream asm_str;
  switch (gArch->arch_name) {
    case remill::kArchInvalid:
      LOG(FATAL)
          << "Cannot generate native-to-lifted entrypoint thunk for "
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
      LOG(ERROR)
          << "TODO: Create a native-to-lifted callback for the "
          << GetArchName(gArch->arch_name) << " instruction set.";
      asm_str << "nop;";
      break;

    default:
      LOG(FATAL)
          << "Cannot create native-to-lifted callback for the "
          << GetArchName(gArch->arch_name) << " instruction set.";
      break;
  }

  auto void_type = llvm::Type::getVoidTy(*gContext);

  // Create the callback function that calls the inline assembly.
  auto callback_type = llvm::FunctionType::get(void_type, false);
  auto callback_func = llvm::Function::Create(
      callback_type, llvm::GlobalValue::InternalLinkage,  // Tentative linkage.
      callback_name, gModule);

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
  auto asm_func = llvm::InlineAsm::get(
      asm_func_type, asm_str.str(), "*m,*m,~{dirflag},~{fpsr},~{flags}",
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
	  func_wrapper_name.str(), gModule);
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
  ir.CreateRetVoid();

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
  auto stack_type = llvm::ArrayType::get(
      gWordType, FLAGS_explicit_args_stack_size / (gArch->address_size / 8));

  static llvm::GlobalVariable *stack = nullptr;
  if (!stack) {
    stack = new llvm::GlobalVariable(
        *gModule, stack_type, false, llvm::GlobalValue::InternalLinkage,
        llvm::Constant::getNullValue(stack_type), "__mcsema_stack");
    stack->setThreadLocal(true);
  }
  std::vector<llvm::Constant *> indexes(2);
  indexes[0] = llvm::ConstantInt::get(gWordType, 0);
  indexes[1] = llvm::ConstantInt::get(
      gWordType, stack_type->getNumElements() - 8);

#if LLVM_VERSION_NUMBER <= LLVM_VERSION(3, 6)
  auto gep = llvm::ConstantExpr::getInBoundsGetElementPtr(stack, indexes);
#else
  auto gep = llvm::ConstantExpr::getInBoundsGetElementPtr(
      nullptr, stack, indexes);
#endif
  return llvm::ConstantExpr::getPtrToInt(gep, gWordType);
}

// Create an array of data for holding thread-local storage.
static llvm::Constant *InitialThreadLocalStorage(void) {
  static llvm::Constant *tls = nullptr;
  if (tls) {
    return tls;
  }

  auto tls_type = llvm::ArrayType::get(
      gWordType, 4096 / (gArch->address_size / 8));

  auto tls_var = new llvm::GlobalVariable(
      *gModule, tls_type, false, llvm::GlobalValue::InternalLinkage,
      llvm::Constant::getNullValue(tls_type), "__mcsema_tls");
  tls_var->setThreadLocal(true);

  std::vector<llvm::Constant *> indexes(2);
  indexes[0] = llvm::ConstantInt::get(gWordType, 0);
  indexes[1] = indexes[0];

#if LLVM_VERSION_NUMBER <= LLVM_VERSION(3, 6)
  auto gep = llvm::ConstantExpr::getInBoundsGetElementPtr(tls_var, indexes);
#else
  auto gep = llvm::ConstantExpr::getInBoundsGetElementPtr(
      nullptr, tls_var, indexes);
#endif

  tls = llvm::ConstantExpr::getPtrToInt(gep, gWordType);
  return tls;
}

// Figure ouf the byte offset of the stack pointer register in the `State`
// structure.
static uint64_t GetStackPointerOffset(void) {
  CallingConvention cc(gArch->DefaultCallingConv());
  std::string sp_name(cc.StackPointerVarName());
  auto reg = gArch->RegisterByName(sp_name);
  CHECK(reg != nullptr)
      << "Could not identify stack pointer " << sp_name
      << " register in State structure";

  return reg->offset;
}

// Create a global register state pointer to pass to lifted functions.
static llvm::GlobalVariable *GetStatePointer(void) {
  static llvm::GlobalVariable *state_ptr = nullptr;
  if (state_ptr) {
    return state_ptr;
  }

  auto lifted_func_type = LiftedFunctionType();
  auto state_ptr_type = lifted_func_type->getFunctionParamType(
      remill::kStatePointerArgNum);
  auto state_type = llvm::dyn_cast<llvm::PointerType>(
      state_ptr_type)->getElementType();

  // State is initialized with zeroes. Each callback/entrypoint set
  // appropriate value to stack pointer. This is needed because of
  // thread_local
  auto state_init = llvm::ConstantAggregateZero::get(state_type);
  state_ptr = new llvm::GlobalVariable(
      *gModule, state_type, false, llvm::GlobalValue::InternalLinkage,
      state_init, "__mcsema_reg_state");
  state_ptr->setThreadLocal(true);
  return state_ptr;
}

static llvm::Function *CreateVerifyRegState(void) {
  auto *func_type = llvm::FunctionType::get(llvm::Type::getVoidTy(*gContext),
                                            {}, false);
  llvm::Constant *c_func = gModule->getOrInsertFunction(
      "__mcsema_verify_reg_state",
      func_type);
  auto func = llvm::dyn_cast<llvm::Function>(c_func);
  CHECK(func) << "Could not cast "
      << remill::LLVMThingToString(c_func)
      << " to llvm::Function *";

  auto sp_offset = GetStackPointerOffset();
  auto reg_state = GetStatePointer();

  auto entry_block = llvm::BasicBlock::Create(*gContext, "entry", func);
  auto is_null_block = llvm::BasicBlock::Create(*gContext, "is_null", func);
  auto end_block = llvm::BasicBlock::Create(*gContext, "end", func);
  llvm::IRBuilder<> ir(entry_block);

  // Need to find out where stack pointer is and known information is
  // byte offset in state structure
  auto byte_ty = llvm::Type::getInt8PtrTy(*gContext);
  unsigned ptr_size = static_cast<unsigned>(gArch->address_size);
  auto reg_ptr_ty = llvm::PointerType::getIntNPtrTy(*gContext, ptr_size);

  //TODO(lukas): remove after abi_libraries patch gets merged into master
  auto GetConstantInt = [&](unsigned size, uint64_t value) {
    return llvm::ConstantInt::get(
        llvm::Type::getIntNTy(*gContext, size), value);
  };
  auto casted_reg_state = ir.CreateBitCast(reg_state, byte_ty);
  auto rsp = ir.CreateGEP(casted_reg_state,
                          GetConstantInt(64, sp_offset));
  auto casted_rsp = ir.CreateBitCast(rsp, reg_ptr_ty);
  auto rsp_val = ir.CreateLoad(casted_rsp,
                               llvm::Type::getIntNTy(*gContext, ptr_size));
  auto comparison = ir.CreateICmpEQ(rsp_val, GetConstantInt(ptr_size, 0));
  ir.CreateCondBr(comparison, is_null_block, end_block);

  // Stack pointer is pointing at nothing, so we need to set it up
  ir.SetInsertPoint(is_null_block);
  ir.CreateStore(InitialStackPointerValue(), casted_rsp);
  ir.CreateBr(end_block);

  // Last block just returns void
  ir.SetInsertPoint(end_block);
  ir.CreateRetVoid();

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
llvm::Function *GetVerifyRegState(void) {
  static llvm::Function *func = nullptr;
  if (!func) {
    func = CreateVerifyRegState();
  }
  return func;
}

// Inserts call to __mcsema_verify_reg_state as first instruction in function
void InsertVerifyFunction(llvm::Function *func) {
  auto &first_inst = func->front().front();
  auto verify_func = GetVerifyRegState();
  llvm::CallInst::Create(verify_func, {}, "", &first_inst);
}

// Implements a stub for an externally defined function in such a way that
// the external is explicitly called, and arguments from the modeled CPU
// state are passed into the external.
static llvm::Function *ImplementExplicitArgsEntryPoint(
    const NativeObject *cfg_func, const std::string &name) {

  auto num_args = FLAGS_explicit_args_count;
  if (name == "main") {
    num_args = 3;
  }

  // These function needs to be created with 0 arguments, otherwise
  // lift could crash when using both --explicit_args
  // and --libc_constructor (issue #424)
  const static std::array<std::string, 4> zero_argument_functions = {{
    "__libc_csu_init",
    "__libc_csu_fini",
    "init",
    "fini"
  }};

  for (const auto &zero_func_name : zero_argument_functions) {
    if (cfg_func->name == zero_func_name) {
      num_args = 0;
      break;
    }
  }

  // The the lifted function type so that we can get things like the memory
  // pointer type and stuff.
  auto bb = remill::BasicBlockFunction(gModule);
  auto state_ptr_arg = remill::NthArgument(bb, remill::kStatePointerArgNum);
  auto mem_ptr_arg = remill::NthArgument(bb, remill::kMemoryPointerArgNum);
  auto pc_arg = remill::NthArgument(bb, remill::kPCArgNum);
  auto pc_type = pc_arg->getType();

  LOG(INFO)
      << "Generating explicit argument entrypoint function for "
      << name << ", calling into " << cfg_func->lifted_name;

  std::vector<llvm::Type *> arg_types(num_args, pc_type);

  auto func_type = llvm::FunctionType::get(pc_type, arg_types, false);
  auto func = llvm::Function::Create(
      func_type, llvm::GlobalValue::InternalLinkage, name, gModule);

  remill::ValueMap value_map;
  value_map[mem_ptr_arg] = llvm::Constant::getNullValue(mem_ptr_arg->getType());
  value_map[pc_arg] = llvm::ConstantInt::get(pc_type, cfg_func->ea);
  value_map[state_ptr_arg] = GetStatePointer();

  remill::CloneFunctionInto(bb, func, value_map);

  // NOTE(pag): Some versions of LLVM use `AttributeSet`, while others
  //            use `AttributeList`.
  decltype(func->getAttributes()) attr_set_or_list;
  func->setAttributes(attr_set_or_list);
  func->addFnAttr(llvm::Attribute::NoInline);
  func->addFnAttr(llvm::Attribute::NoBuiltin);

  InsertVerifyFunction(func);

  if (FLAGS_stack_protector) {
    func->addFnAttr(llvm::Attribute::StackProtectReq);
  }

  // Remove the `return` in code cloned from `__remill_basic_block`.
  auto block = &(func->front());
  auto term = block->getTerminator();
  term->eraseFromParent();

  CallingConvention loader(gArch->DefaultCallingConv());

  loader.StoreThreadPointer(block, InitialThreadLocalStorage());

  // Save off the old stack pointer for later.
  auto old_sp = loader.LoadStackPointer(block);

  // Call the `__mcsema_early_init` function to make sure all lazy cross-
  // reference initializers have been installed before any lifted bitcode
  // is executed.
  llvm::CallInst::Create(GetOrCreateMcSemaInitializer(), "", block);

  // Send in argument values.
  std::vector<llvm::Value *> explicit_args;
  for (auto &arg : func->args()) {
    explicit_args.push_back(&arg);
  }
  loader.StoreArguments(block, explicit_args);

  // Allocate any space needed on the stack for a return address.
  loader.AllocateReturnAddress(block);

  // Call the lifted function.
  std::vector<llvm::Value *> args(3);
  args[remill::kMemoryPointerArgNum] = remill::LoadMemoryPointer(block);
  args[remill::kStatePointerArgNum] = value_map[state_ptr_arg];
  args[remill::kPCArgNum] = value_map[pc_arg];

  llvm::CallInst::Create(
      gModule->getFunction(cfg_func->lifted_name), args, "", block);

  // Restore the old stack pointer.
  loader.StoreStackPointer(block, old_sp);

  // Extract and return the return value from the state structure/memory.
  llvm::ReturnInst::Create(
      *gContext, loader.LoadReturnValue(block, pc_type), block);

  if (!FLAGS_pc_annotation.empty()) {
    legacy::AnnotateInsts(func, cfg_func->ea);
  }

  return func;
}

static llvm::Function *GetOrCreateCallback(const NativeObject *cfg_func,
                                           const std::string &callback_name) {
  CHECK(!cfg_func->is_external)
      << "Cannot get entry point thunk for external function "
      << cfg_func->name;

  auto callback_func = gModule->getFunction(callback_name);
  if (callback_func) {
    return callback_func;
  }

  if (FLAGS_explicit_args) {
    return ImplementExplicitArgsEntryPoint(cfg_func, callback_name);
  } else {
    return ImplementNativeToLiftedCallback(cfg_func, callback_name);
  }
}

// Implements a stub for an externally defined function in such a way that,
// when executed, this stub redirects control flow into the actual external
// function.
static void ImplementLiftedToNativeCallback(
    llvm::Function *callback_func, llvm::Function *extern_func,
    const NativeExternalFunction *cfg_func) {

  callback_func->addFnAttr(llvm::Attribute::NoInline);

  auto block = llvm::BasicBlock::Create(*gContext, "", callback_func);

  // The third argument of lifted functions (including things like
  // `__remill_function_call`) is the program counter. Make sure that
  // the "real" address of the external is passed in as that third argument
  // because it's likely that whatever was in the CFG makes no sense
  // in the lifted code.
  auto args = remill::LiftedFunctionArgs(block);
  args[remill::kPCArgNum] = llvm::ConstantExpr::getPtrToInt(
      extern_func, gWordType);

  llvm::IRBuilder<> ir(block);
  auto handler_call = ir.CreateCall(DetachCallValueFunc(), args);
  ir.CreateRet(handler_call);
}

// Implements a stub for an externally defined function in such a way that
// the external is explicitly called, and arguments from the modeled CPU
// state are passed into the external.
static void ImplementExplicitArgsExitPoint(
    llvm::Function *callback_func, llvm::Function *extern_func,
    const NativeExternalFunction *cfg_func) {

  remill::CloneBlockFunctionInto(callback_func);

  // Always inline so that static analyses of the bitcode don't need to dive
  // into an extra function just to see the intended call.
  callback_func->removeFnAttr(llvm::Attribute::NoInline);
  callback_func->addFnAttr(llvm::Attribute::InlineHint);
  callback_func->addFnAttr(llvm::Attribute::AlwaysInline);
  callback_func->removeFnAttr(llvm::Attribute::NoUnwind);

  if (FLAGS_stack_protector) {
    callback_func->addFnAttr(llvm::Attribute::StackProtectReq);
  }

  LOG(INFO)
      << "Generating " << cfg_func->num_args
      << " argument getters in function "
      << cfg_func->lifted_name << " for external " << cfg_func->name;

  auto func_type = extern_func->getFunctionType();
  auto num_params = func_type->getNumParams();
  CallingConvention loader(cfg_func->cc);

  if (num_params > cfg_func->num_args) {
    LOG(ERROR)
        << "Function " << cfg_func->name << " may be incorrectly "
        << "specified in the CFG with " << cfg_func->num_args
        << " whereas the bitcode function has " << num_params
        << ": " << remill::LLVMThingToString(extern_func);

  } else if (num_params != cfg_func->num_args) {
    CHECK(num_params < cfg_func->num_args && func_type->isVarArg())
        << "Function " << remill::LLVMThingToString(extern_func)
        << " is expected to be able to take " << cfg_func->num_args
        << " arguments.";
  }

  auto block = &(callback_func->back());
  auto actual_num_args = std::max<unsigned>(num_params, cfg_func->num_args);

  // create call to function and args
  std::vector<llvm::Value *> call_args;
  auto arg_iter = extern_func->arg_begin();
  for (auto i = 0U; i < actual_num_args; i++) {
    llvm::Type *param_type = nullptr;
    bool is_byval = false;
    if (i < num_params) {
      param_type = func_type->getParamType(i);
      is_byval = arg_iter->hasByValAttr();
      ++arg_iter;
    }
    call_args.push_back(loader.LoadNextArgument(block, param_type, is_byval));
  }

  // Now that we've read the argument values, we want to free up the space that
  // the emulated caller set up, so that when we eventually return, things are
  // in the expected state.
  loader.FreeReturnAddress(block);
  loader.FreeArguments(block);

  llvm::IRBuilder<> ir(block);
  loader.StoreReturnValue(block, ir.CreateCall(extern_func, call_args));

  ir.CreateRet(remill::LoadMemoryPointer(block));
}

}  // namespace

// Get a callback function for an internal function that can be referenced by
// internal code.
llvm::Function *GetNativeToLiftedCallback(const NativeObject *cfg_func) {
  if (cfg_func->is_exported) {
    return GetNativeToLiftedEntryPoint(cfg_func);
  } else {
    std::stringstream ss;
    ss << "callback_" << cfg_func->lifted_name;
    return GetOrCreateCallback(cfg_func, ss.str());
  }
}

// Get a callback function for an internal function.
llvm::Function *GetNativeToLiftedEntryPoint(const NativeObject *cfg_func) {
  return GetOrCreateCallback(cfg_func, cfg_func->name);
}

// Get a callback function for an external function that can be referenced by
// internal code.
llvm::Function *GetLiftedToNativeExitPoint(const NativeObject *cfg_func_) {
  CHECK(cfg_func_->is_external)
      << "Cannot get exit point thunk for internal function "
      << cfg_func_->name << " at " << std::hex << cfg_func_->ea;

  auto cfg_func = reinterpret_cast<const NativeExternalFunction *>(cfg_func_);
  CHECK(cfg_func->name != cfg_func->lifted_name);

  auto callback_func = gModule->getFunction(cfg_func->lifted_name);
  if (callback_func) {
    return callback_func;
  }

  auto extern_func = gModule->getFunction(cfg_func->name);
  CHECK(extern_func != nullptr)
      << "Cannot find declaration or definition for external function "
      << cfg_func->name;

  // Stub that will marshal lifted state into the native state.
  callback_func = llvm::Function::Create(LiftedFunctionType(),
                                         llvm::GlobalValue::InternalLinkage,
                                         cfg_func->lifted_name, gModule);

  // Pass through the memory and state pointers, and pass the destination
  // (native external function address) as the PC argument.
  if (FLAGS_explicit_args || cfg_func->is_explicit) {
    ImplementExplicitArgsExitPoint(callback_func, extern_func, cfg_func);

  // We are going from lifted to native code. We don't need an assembly stub
  // because `__remill_function_call` already does the right thing.
  } else {
    ImplementLiftedToNativeCallback(callback_func, extern_func, cfg_func);
  }

  if (!FLAGS_pc_annotation.empty()) {
    legacy::AnnotateInsts(callback_func, cfg_func->ea);
  }
  return callback_func;
}

// Get a function that goes from the current lifted state into native state,
// where we don't know where the native destination actually is.
llvm::Function *GetLiftedToNativeExitPoint(ExitPointKind kind) {
  if (!FLAGS_explicit_args) {
    switch (kind) {
      case kExitPointJump:
        return gModule->getFunction("__remill_jump");
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

  // Stub that will marshal lifted state into the native state.
  callback_func = llvm::Function::Create(LiftedFunctionType(),
                                         llvm::GlobalValue::InternalLinkage,
                                         "__mcsema_detach_call_value", gModule);

  remill::CloneBlockFunctionInto(callback_func);

  // We don't want this function to be inlined, since it was causing problems
  // with llvm optimizations run by runO3

  CallingConvention loader(gArch->DefaultCallingConv());

  auto block = &(callback_func->back());

  std::vector<llvm::Value *> call_args;
  for (uint64_t i = 0U; i < FLAGS_explicit_args_count; i++) {
    call_args.push_back(loader.LoadNextArgument(block));
  }

  std::vector<llvm::Type *> arg_types(FLAGS_explicit_args_count,
                                      remill::AddressType(gModule));

  auto pc = remill::LoadProgramCounter(block);
  auto func_ptr_ty = llvm::PointerType::get(
      llvm::FunctionType::get(call_args[0]->getType(), arg_types, false), 0);

  llvm::IRBuilder<> ir(block);
  loader.StoreReturnValue(
      block, ir.CreateCall(ir.CreateIntToPtr(pc, func_ptr_ty), call_args));

  // This means that indirect call happened and caller pushed his return
  // address, which he expects callee will pop. However callee is one
  // of entrypoints/callbacks, which freeze the %rsp, so we need to pop it
  // for callee
  loader.FreeReturnAddress(block);

  ir.CreateRet(remill::LoadMemoryPointer(block));

  return callback_func;
}

}  // namespace mcsema
