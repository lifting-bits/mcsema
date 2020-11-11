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

#include "mcsema/BC/Function.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wswitch-enum"
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/IR/CallSite.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Type.h>
#include <llvm/Transforms/Utils/Cloning.h>
#pragma clang diagnostic pop

#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Annotate.h>
#include <remill/BC/Compat/Error.h>
#include <remill/BC/Compat/ScalarTransforms.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Lifter.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Callback.h"
#include "mcsema/BC/Instruction.h"
#include "mcsema/BC/Legacy.h"
#include "mcsema/BC/Lift.h"
#include "mcsema/BC/Optimize.h"
#include "mcsema/BC/Segment.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

DECLARE_bool(legacy_mode);
DECLARE_bool(explicit_args);

DEFINE_bool(add_state_tracer, false,
            "Add a debug function that prints out the register state before "
            "each lifted instruction execution.");

DEFINE_bool(add_func_state_tracer, false,
            "Add a debug function that prints out the register state before "
            "each lifted function execution.");

DEFINE_string(
    trace_reg_values, "",
    "Add a debug function that prints out the specified register values "
    "before each lifted instruction execution. The registers printed out "
    "always include the current program counter, as well as the registers "
    "in specified in this option (as a comma-separated list).");

DEFINE_bool(add_pc_tracer, false,
            "Add a debug function that is invoked just before every lifted "
            "instruction, where the PC of the instruction is passed into the "
            "tracer. This is similar to --trace_reg_values, but it doesn't "
            "negatively impact optimizations.");

DEFINE_bool(
    add_breakpoints, false,
    "Add 'breakpoint' functions between every lifted instruction. This "
    "allows one to set a breakpoint, in the lifted code, just before a "
    "specific lifted instruction is executed. This is a debugging aid.");

DEFINE_string(
    exception_personality_func, "__gxx_personality_v0",
    "Add a personality function for lifting exception handling "
    "routine. Assigned __gxx_personality_v0 as default for c++ ABTs.");

DEFINE_bool(stack_protector, false,
            "Annotate functions so that if the bitcode "
            "is compiled with -fstack-protector-all then the stack protection "
            "guards will be added.");

namespace mcsema {
namespace {

static llvm::Value *LoadMemoryPointer(const TranslationContext &ctx,
                                      llvm::BasicBlock *block) {
  return ctx.lifter->LoadRegValue(block, ctx.state_ptr, "MEMORY");
}

static llvm::Value *LoadMemoryPointerRef(const TranslationContext &ctx,
                                         llvm::BasicBlock *block) {
  return ctx.lifter->LoadRegAddress(block, ctx.state_ptr, "MEMORY");
}

static llvm::Value *LoadStatePointer(const TranslationContext &,
                                     llvm::BasicBlock *block) {
  return remill::NthArgument(block->getParent(), remill::kStatePointerArgNum);
}

static llvm::Value *LoadProgramCounter(const TranslationContext &ctx,
                                       llvm::BasicBlock *block) {
  return ctx.lifter->LoadRegValue(block, ctx.state_ptr, "PC");
}

static llvm::Value *LoadProgramCounterRef(const TranslationContext &ctx,
                                          llvm::BasicBlock *block) {
  return ctx.lifter->LoadRegAddress(block, ctx.state_ptr, "PC");
}

static llvm::Value *LoadNextProgramCounter(const TranslationContext &ctx,
                                           llvm::BasicBlock *block) {
  return ctx.lifter->LoadRegValue(block, ctx.state_ptr, "NEXT_PC");
}

static llvm::Value *LoadNextProgramCounterRef(const TranslationContext &ctx,
                                              llvm::BasicBlock *block) {
  return ctx.lifter->LoadRegAddress(block, ctx.state_ptr, "NEXT_PC");
}

// Get the register tracer. This is useful when debugging, where the runtime
// implements the register tracer in a way that prints out all general purpose
// register names and their values before each lifted instruction. This trace
// can help discover the source of an emulation divergence, among other things.
static llvm::Function *GetValueTracer(void) {
  static llvm::Function *gValueTracer = nullptr;
  if (gValueTracer) {
    return gValueTracer;
  }

  gValueTracer = gModule->getFunction("__mcsema_value_tracer");
  if (gValueTracer) {
    return gValueTracer;
  }

  gValueTracer = llvm::Function::Create(gArch->LiftedFunctionType(),
                                        llvm::GlobalValue::PrivateLinkage,
                                        "__mcsema_value_tracer", gModule.get());
  gValueTracer->removeFnAttr(llvm::Attribute::NoDuplicate);
  gValueTracer->addFnAttr(llvm::Attribute::AlwaysInline);
  gValueTracer->addFnAttr(llvm::Attribute::InlineHint);
  gValueTracer->addFnAttr(llvm::Attribute::ReadNone);
  gValueTracer->removeFnAttr(llvm::Attribute::OptimizeNone);
  gValueTracer->removeFnAttr(llvm::Attribute::NoInline);

  llvm::Value *mem_ptr =
      remill::NthArgument(gValueTracer, remill::kMemoryPointerArgNum);
  auto printf = gModule->getFunction("__mcsema_printf");
  auto i32_type = llvm::Type::getInt8Ty(*gContext);
  if (!printf) {
    auto i8_type = llvm::Type::getInt8Ty(*gContext);
    llvm::Type *param_types_2[] = {mem_ptr->getType(),
                                   llvm::PointerType::get(i8_type, 0)};

    printf = llvm::Function::Create(
        llvm::FunctionType::get(mem_ptr->getType(), param_types_2, true),
        llvm::GlobalValue::ExternalLinkage, "__mcsema_printf", gModule.get());
  }

  printf->addFnAttr(llvm::Attribute::ReadNone);

  std::stringstream ss;
  std::vector<llvm::Value *> args;
  args.push_back(
      remill::NthArgument(gValueTracer, remill::kMemoryPointerArgNum));
  args.push_back(nullptr);  // Format.
  args.push_back(remill::NthArgument(gValueTracer, remill::kPCArgNum));

  auto format = gArch->address_size == 64 ? "=%016llx " : "=%08x ";
  auto block = llvm::BasicBlock::Create(*gContext, "", gValueTracer);
  auto state_ptr =
      remill::NthArgument(gValueTracer, remill::kStatePointerArgNum);

  auto pc_reg = gArch->RegisterByName(gArch->ProgramCounterRegisterName());
  ss << "pc" << format;

  std::unordered_set<std::string> regs;
  std::stringstream rs;
  rs << FLAGS_trace_reg_values;
  for (std::string reg_name; std::getline(rs, reg_name, ',');) {
    const auto reg = gArch->RegisterByName(reg_name);
    if (reg->type == gWordType && reg != pc_reg) {
      ss << reg->name << format;
      args.push_back(
          new llvm::LoadInst(reg->AddressOf(state_ptr, block), "", block));
    }
  }
  ss << '\n';

  auto format_str =
      llvm::ConstantDataArray::getString(*gContext, ss.str(), true);
  auto format_var =
      new llvm::GlobalVariable(*gModule, format_str->getType(), true,
                               llvm::GlobalValue::InternalLinkage, format_str);

  llvm::Constant *indices[] = {llvm::ConstantInt::getNullValue(i32_type),
                               llvm::ConstantInt::getNullValue(i32_type)};

  llvm::IRBuilder<> ir(block);
  args[1] = llvm::ConstantExpr::getInBoundsGetElementPtr(format_str->getType(),
                                                         format_var, indices);
  mem_ptr = ir.CreateCall(printf, args);
  ir.CreateRet(mem_ptr);

  return gValueTracer;
}

// Get the register tracer. This is useful when debugging, where the runtime
// implements the register tracer in a way that prints out all general purpose
// register names and their values before each lifted instruction. This trace
// can help discover the source of an emulation divergence, among other things.
static llvm::Function *GetRegTracer(void) {
  static llvm::Function *gRegTracer = nullptr;
  if (!gRegTracer) {
    gRegTracer = gModule->getFunction("__mcsema_reg_tracer");
    if (!gRegTracer) {
      gRegTracer = llvm::Function::Create(gArch->LiftedFunctionType(),
                                          llvm::GlobalValue::ExternalLinkage,
                                          "__mcsema_reg_tracer", gModule.get());
      gRegTracer->addFnAttr(llvm::Attribute::NoDuplicate);
      gRegTracer->removeFnAttr(llvm::Attribute::AlwaysInline);
      gRegTracer->removeFnAttr(llvm::Attribute::InlineHint);
      gRegTracer->addFnAttr(llvm::Attribute::OptimizeNone);
      gRegTracer->addFnAttr(llvm::Attribute::NoInline);
      gRegTracer->addFnAttr(llvm::Attribute::ReadNone);
    }
  }
  return gRegTracer;
}

// Get the PC tracer for a given program counter. This function is useful when
// integrating with KLEE. A call to this function is injected before every
// lifted instruction. If this function is implemented as a KLEE special
// function handler, then the second argument is the emulated program counter,
// and a logical stack trace feature can be implemented by recording these
// program counters into a KLEE execution state.
static llvm::Function *GetPCTracer(void) {
  static llvm::Function *gPCTracer = nullptr;
  if (!gPCTracer) {
    gPCTracer = gModule->getFunction("__mcsema_pc_tracer");
    if (!gPCTracer) {
      llvm::Type *arg_types[1] = {gWordType};
      auto func_type = llvm::FunctionType::get(llvm::Type::getVoidTy(*gContext),
                                               arg_types, false);
      gPCTracer =
          llvm::Function::Create(func_type, llvm::GlobalValue::ExternalLinkage,
                                 "__mcsema_pc_tracer", gModule.get());
      gPCTracer->removeFnAttr(llvm::Attribute::AlwaysInline);
      gPCTracer->removeFnAttr(llvm::Attribute::InlineHint);
      gPCTracer->addFnAttr(llvm::Attribute::NoDuplicate);
      gPCTracer->addFnAttr(llvm::Attribute::OptimizeNone);
      gPCTracer->addFnAttr(llvm::Attribute::NoInline);
    }
  }
  return gPCTracer;
}

// Get the breakpoint function for a given program counter. These functions
// are useful for debugging. For example, if you are debugging lifted bitcode,
// and want to stop execution at the logical location where the instruction
// at `0xf00` resides, then in a debugger, you would add your breakpoint on
// the `breakpoint_f00` function.
static llvm::Function *GetBreakPoint(uint64_t pc) {
  std::stringstream ss;
  ss << "breakpoint_" << std::hex << pc;

  const auto func_name = ss.str();
  auto func = gModule->getFunction(func_name);
  if (func) {
    return func;
  }

  static const auto mem_ptr_type = gArch->MemoryPointerType();
  llvm::Type *const params[1] = {mem_ptr_type};
  const auto fty = llvm::FunctionType::get(mem_ptr_type, params, false);
  func = llvm::Function::Create(fty, llvm::GlobalValue::ExternalLinkage,
                                func_name, gModule.get());

  // Make sure to keep this function around (along with `ExternalLinkage`).
  func->addFnAttr(llvm::Attribute::OptimizeNone);
  func->removeFnAttr(llvm::Attribute::AlwaysInline);
  func->removeFnAttr(llvm::Attribute::InlineHint);
  func->addFnAttr(llvm::Attribute::NoInline);
  func->addFnAttr(llvm::Attribute::ReadNone);

  llvm::IRBuilder<> ir(llvm::BasicBlock::Create(*gContext, "", func));
  ir.CreateRet(remill::NthArgument(func, 0));
  return func;
}

// Get the personality function of exception handling ABIs.
// For libstdc++ it will be reference to `__gxx_personality_v0`
static llvm::Function *GetPersonalityFunction(void) {
  static llvm::Function *personality_func = nullptr;
  if (personality_func) {
    return personality_func;
  }

  const auto &personality_func_name = FLAGS_exception_personality_func;

  // The personality function is lifted as global variable. Check and erase the
  // variable before declaring it as the function.
  if (auto personality_func_var =
          gModule->getGlobalVariable(personality_func_name);
      personality_func_var) {
    if (personality_func_var->hasNUsesOrMore(1)) {
      LOG(ERROR) << "Renaming existing exception personality variable "
                 << FLAGS_exception_personality_func;
      personality_func_var->setName(FLAGS_exception_personality_func +
                                    "__original");
    } else {
      personality_func_var->eraseFromParent();
    }
  }

  personality_func = gModule->getFunction(personality_func_name);
  if (personality_func == nullptr) {
    personality_func = llvm::Function::Create(
        llvm::FunctionType::get(llvm::Type::getInt32Ty(*gContext), true),
        llvm::Function::ExternalLinkage, personality_func_name, gModule.get());
  }

  return personality_func;
}

// The exception handling prologue function clears the stack and set the
// stack and frame pointer correctly before jumping to the handler routine.
static llvm::Function *GetExceptionHandlerPrologue(void) {
  auto dword_type = llvm::Type::getInt32Ty(*gContext);
  auto exception_handler = gModule->getFunction("__mcsema_exception_ret");
  if (exception_handler == nullptr) {
    llvm::Type *args_type[] = {gWordType, gWordType, dword_type};
    auto func_type = llvm::FunctionType::get(llvm::Type::getVoidTy(*gContext),
                                             args_type, false);
    exception_handler =
        llvm::Function::Create(func_type, llvm::Function::ExternalWeakLinkage,
                               "__mcsema_exception_ret", gModule.get());
  }
  return exception_handler;
}

// `__mcsema_get_type_index` function returns the RDX register holding
// the exception type index. It also saves the RAX register state.
static llvm::Function *GetExceptionTypeIndex(void) {
  auto get_index_func = gModule->getFunction("__mcsema_get_type_index");
  if (!get_index_func) {
    get_index_func =
        llvm::Function::Create(llvm::FunctionType::get(gWordType, false),
                               llvm::GlobalValue::ExternalWeakLinkage,
                               "__mcsema_get_type_index", gModule.get());
  }

  return get_index_func;
}

enum class PCValueKind { kSymbolicPC, kConcretePC, kUndefPC };

// Add a invoke to another function and then update the memory pointer with the
// result of the function. It also needs to stash the stack and frame pointer which
// can be restored before handling the exception handler.
static void
InlineSubFuncInvoke(const TranslationContext &ctx, llvm::BasicBlock *block,
                    llvm::Function *sub, llvm::BasicBlock *if_normal,
                    llvm::BasicBlock *if_exception,
                    const NativeFunction *cfg_func,
                    PCValueKind pc_kind = PCValueKind::kSymbolicPC) {

  llvm::IRBuilder<> ir(block);
  auto get_sp_func = gModule->getFunction("__mcsema_get_stack_pointer");
  if (!get_sp_func) {
    get_sp_func =
        llvm::Function::Create(llvm::FunctionType::get(gWordType, false),
                               llvm::GlobalValue::ExternalLinkage,
                               "__mcsema_get_stack_pointer", gModule.get());
  }

  auto sp_var = ir.CreateCall(get_sp_func);
  ir.CreateStore(sp_var, ctx.stack_ptr_var);

  auto get_bp_func = gModule->getFunction("__mcsema_get_frame_pointer");
  if (!get_bp_func) {
    get_bp_func =
        llvm::Function::Create(llvm::FunctionType::get(gWordType, false),
                               llvm::GlobalValue::ExternalLinkage,
                               "__mcsema_get_frame_pointer", gModule.get());
  }

  llvm::Value *args[remill::kNumBlockArgs];
  args[remill::kMemoryPointerArgNum] = LoadMemoryPointer(ctx, block);
  args[remill::kStatePointerArgNum] = LoadStatePointer(ctx, block);

  if (PCValueKind::kSymbolicPC == pc_kind) {
    args[remill::kPCArgNum] = LoadNextProgramCounter(ctx, block);
  } else if (PCValueKind::kUndefPC == pc_kind) {
    args[remill::kPCArgNum] = llvm::UndefValue::get(gWordType);
  } else {
    args[remill::kPCArgNum] = llvm::ConstantInt::get(gWordType, ctx.inst.pc);
  }

  auto bp_var = ir.CreateCall(get_bp_func);
  ir.CreateStore(bp_var, ctx.frame_ptr_var);
  auto invoke = ir.CreateInvoke(sub, if_normal, if_exception, args, "");
  invoke->setCallingConv(sub->getCallingConv());

  // Store the memory pointer down the normal path of the invoked function.
  auto mem_ptr_ref = LoadMemoryPointerRef(ctx, if_normal);
  ir.SetInsertPoint(if_normal);
  ir.CreateStore(invoke, mem_ptr_ref);
}

// Add a call to another function, and then update the memory pointer with the
// result of the function.
static llvm::Value *LiftSubFuncCall(
    const TranslationContext &ctx, llvm::BasicBlock *block, llvm::Function *sub,
    PCValueKind pc_kind = PCValueKind::kSymbolicPC, uint64_t concrete_pc = 0) {
  llvm::Value *args[remill::kNumBlockArgs];
  args[remill::kMemoryPointerArgNum] = LoadMemoryPointer(ctx, block);
  args[remill::kStatePointerArgNum] = LoadStatePointer(ctx, block);

  if (PCValueKind::kSymbolicPC == pc_kind) {
    args[remill::kPCArgNum] = LoadNextProgramCounter(ctx, block);
  } else if (PCValueKind::kUndefPC == pc_kind) {
    args[remill::kPCArgNum] = llvm::UndefValue::get(gWordType);
  } else if (concrete_pc) {
    args[remill::kPCArgNum] = llvm::ConstantInt::get(gWordType, concrete_pc);
  } else {
    args[remill::kPCArgNum] = llvm::ConstantInt::get(gWordType, ctx.inst.pc);
  }

  auto call = llvm::CallInst::Create(sub, args, "", block);
  call->setCallingConv(sub->getCallingConv());
  auto mem_ptr = LoadMemoryPointerRef(ctx, block);
  (void) new llvm::StoreInst(call, mem_ptr, block);
  return call;
}

// Wrap the lifted function `cfg_func` with its type specification, if any, and
// provide a lifted interface to it.
static llvm::Function *CallableLiftedFunc(const NativeFunction *cfg_func,
                                          llvm::Function *fallback) {

  if (cfg_func->callable_lifted_function) {
    return cfg_func->callable_lifted_function;

  } else {
    LOG(ERROR) << "Falling back on " << cfg_func->name;
    cfg_func->callable_lifted_function = fallback;
    return fallback;
  }
}

// Find an external function associated with this indirect jump.
static llvm::Function *DevirtualizeIndirectFlow(TranslationContext &ctx,
                                                llvm::Function *fallback) {
  if (!ctx.cfg_inst) {
    return fallback;
  }

  if (const auto flow = ctx.cfg_inst->flow; flow) {
    if (auto cfg_func = ctx.cfg_module->TryGetFunction(flow->target_ea);
        cfg_func) {
      return CallableLiftedFunc(cfg_func, fallback);
    }
  }

  return fallback;
}

// Try to find a function. We start by assuming that `target_pc` is an
// absolute address for the function. This is usually the case for direct
// function calls internal to a binary. However, if the function is actually
// an external function then we try to return the external version of the
// function.
static std::pair<const NativeFunction *, llvm::Function *>
FindFunction(TranslationContext &ctx, uint64_t target_pc,
             const remill::IntrinsicTable &intrinsics) {

  const NativeFunction *cfg_func = nullptr;
  if (ctx.cfg_inst) {
    if (auto flow = ctx.cfg_inst->flow; flow) {
      cfg_func = ctx.cfg_module->TryGetFunction(flow->target_ea);
      if (cfg_func) {
        return {cfg_func,
                CallableLiftedFunc(cfg_func, intrinsics.function_call)};
      }
    }
  }

  cfg_func = ctx.cfg_module->TryGetFunction(target_pc);
  if (cfg_func) {
    return {cfg_func, CallableLiftedFunc(cfg_func, intrinsics.function_call)};
  }

  return {nullptr, nullptr};
}

// Try to decode an instruction.
static bool TryDecodeInstruction(TranslationContext &ctx, uint64_t pc,
                                 bool is_delayed) {

  remill::Instruction &inst = is_delayed ? ctx.delayed_inst : ctx.inst;

  static const auto max_inst_size = gArch->MaxInstructionSize();
  inst.Reset();

  auto byte = ctx.cfg_module->FindByte(pc);
  if (!byte.IsExecutable()) {
    return false;
  }

  // Read the bytes.
  auto &inst_bytes = inst.bytes;
  inst_bytes.reserve(max_inst_size);
  for (auto i = 0u; i < max_inst_size && byte && byte.IsExecutable();
       ++i, byte = ctx.cfg_module->FindNextByte(byte)) {
    auto maybe_val = byte.Value();
    if (remill::IsError(maybe_val)) {
      LOG(ERROR) << "Unable to read balue of byte at " << std::hex
                 << byte.Address() << std::dec << ": "
                 << remill::GetErrorString(maybe_val);
      break;
    } else {
      inst_bytes.push_back(static_cast<char>(remill::GetReference(maybe_val)));
    }
  }

  if (is_delayed) {
    return gArch->DecodeDelayedInstruction(pc, inst.bytes, inst);
  } else {
    return gArch->DecodeInstruction(pc, inst.bytes, inst);
  }
}

static llvm::BasicBlock *GetOrCreateBlock(TranslationContext &ctx, uint64_t pc,
                                          bool force_as_block = false);

// Create a landing pad basic block.
static void CreateLandingPad(TranslationContext &ctx,
                             struct NativeExceptionFrame *eh_entry) {
  std::stringstream ss;

  auto dword_type = llvm::Type::getInt32Ty(*gContext);

  // `__mcsema_exception_ret` argument list
  llvm::Value *args[3];
  auto is_catch = (eh_entry->action_index != 0);
  ss << "landingpad_" << std::hex << eh_entry->lp_ea;
  auto landing_bb =
      llvm::BasicBlock::Create(*gContext, ss.str(), ctx.lifted_func);

  std::vector<llvm::Type *> elem_types = {llvm::Type::getInt8PtrTy(*gContext),
                                          dword_type};

  // TODO(akshayk): Should this struct be packed?
  llvm::IRBuilder<> ir(landing_bb);
  auto exn_type = llvm::StructType::get(*gContext, elem_types, false);

#if LLVM_VERSION_NUMBER > LLVM_VERSION(3, 6)
  auto lpad = ir.CreateLandingPad(exn_type, 1, ss.str());
#else
  auto personality_func = GetPersonalityFunction();
  auto lpad = ir.CreateLandingPad(exn_type, personality_func, 1, ss.str());
#endif

  lpad->setCleanup(!is_catch);

  if (is_catch) {
    std::stringstream g_variable_name_ss;
    std::vector<llvm::Constant *> array_value_const;
    auto catch_all = false;
    unsigned long catch_all_index = 0;

    for (auto &it : eh_entry->type_var) {

      // Check the ttype variables are not null
      auto type = it.second;
      CHECK_NOTNULL(type);
      if (type->ea) {
        lpad->addClause(gModule->getGlobalVariable(type->name));
        auto value = llvm::ConstantInt::get(dword_type, type->size);
        array_value_const.push_back(value);
      } else {
        catch_all = true;
        catch_all_index = type->size;
      }
    }

    if (catch_all) {
      lpad->addClause(llvm::Constant::getNullValue(ir.getInt8PtrTy()));
      array_value_const.push_back(llvm::ConstantInt::get(
          llvm::Type::getInt32Ty(*gContext), catch_all_index));
    }

    // Create the global array to store the type indices of original binary.
    // It is required to map the type indices in the exception table of
    // lifted binary to the original. The runtime routine does an array
    // lookup and fixes the index value for exception type (update the
    // RDX register).
    //
    // E.g.
    //  `gvar_landingpad_xxxxxx = global [5 x i32] [i32 0, i32 4, i32 1, i32 2, i32 3]`
    //
    // The `gvar_landingpad_xxxxxx` will be associated with the landing pad.
    // The variable array index represents the index in lifted binary and the
    // value at the corresponding index maps it in the original. The `0` index
    // value is a dummy, and it is used to avoid further index computation.
    g_variable_name_ss << "gvar_landingpad_" << std::hex << eh_entry->lp_ea;
    auto g_variable_name = g_variable_name_ss.str();
    auto array_type =
        llvm::ArrayType::get(dword_type, eh_entry->type_var.size() + 1);

    if (!gModule->getOrInsertGlobal(g_variable_name, array_type)) {
      LOG_IF(ERROR, 1) << "Can't create the global variable " << g_variable_name
                       << " for the landing pad at" << std::hex
                       << eh_entry->lp_ea << std::dec;
    }

    auto gvar_landingpad = gModule->getGlobalVariable(g_variable_name);
    gvar_landingpad->setLinkage(llvm::GlobalValue::ExternalLinkage);

    // Set the dummy value for index `0`
    array_value_const.push_back(llvm::ConstantInt::get(dword_type, 0));

    std::reverse(array_value_const.begin(), array_value_const.end());
    llvm::ArrayRef<llvm::Constant *> array_value(array_value_const);
    llvm::Constant *const_array =
        llvm::ConstantArray::get(array_type, array_value);
    gvar_landingpad->setInitializer(const_array);
    auto type_index_value2 = ir.CreateCall(GetExceptionTypeIndex());
    auto type_index_value1 = llvm::ConstantInt::get(dword_type, 0);

    // Get the type index from the original binary and set the `RDX` register
    std::vector<llvm::Value *> array_index_vec;
    array_index_vec.push_back(type_index_value1);
    array_index_vec.push_back(type_index_value2);

    auto var_value = ir.CreateGEP(gvar_landingpad, array_index_vec);

#if LLVM_VERSION_NUMBER > LLVM_VERSION(3, 6)
    args[0] = ir.CreateLoad(gWordType, ctx.stack_ptr_var);
    args[1] = ir.CreateLoad(gWordType, ctx.frame_ptr_var);
    args[2] = ir.CreateLoad(dword_type, var_value);
#else
    args[0] = ir.CreateLoad(ctx.stack_ptr_var, true);
    args[1] = ir.CreateLoad(ctx.frame_ptr_var, true);
    args[2] = ir.CreateLoad(var_value, true);
#endif

  } else {
    auto type_index_value = ir.CreateCall(GetExceptionTypeIndex());
#if LLVM_VERSION_NUMBER > LLVM_VERSION(3, 6)
    args[0] = ir.CreateLoad(gWordType, ctx.stack_ptr_var);
    args[1] = ir.CreateLoad(gWordType, ctx.frame_ptr_var);
    args[2] = ir.CreateTruncOrBitCast(type_index_value, dword_type);
#else
    args[0] = ir.CreateLoad(ctx.stack_ptr_var, true);
    args[1] = ir.CreateLoad(ctx.frame_ptr_var, true);
    args[2] = ir.CreateTruncOrBitCast(type_index_value, dword_type);
#endif
  }

  auto handler = GetExceptionHandlerPrologue();
  ir.CreateCall(handler, args);

  // if `ctx.ea_to_block.count(entry->lp_ea) == 0`, the landing pad basic block
  // has not been recovered. Throw a warning in such case.
  LOG_IF(ERROR, !ctx.ea_to_block.count(eh_entry->lp_ea))
      << "Missing block at " << std::hex << eh_entry->lp_ea
      << " for exception landing pad from " << eh_entry->start_ea << std::dec;

  auto lp_entry = GetOrCreateBlock(ctx, eh_entry->lp_ea);
  ir.CreateBr(lp_entry);
  ctx.lp_to_block[eh_entry->lp_ea] = landing_bb;
}

// Lift landing pads within the function.
static void LiftExceptionFrameLP(TranslationContext &ctx,
                                 const NativeFunction *cfg_func) {

  if (ctx.cfg_func->eh_frame.empty()) {
    return;
  }

  const auto lifted_func = ctx.lifted_func;
  lifted_func->addFnAttr(llvm::Attribute::OptimizeNone);
  lifted_func->removeFnAttr(llvm::Attribute::NoUnwind);
  lifted_func->addFnAttr(llvm::Attribute::UWTable);

#if LLVM_VERSION_NUMBER > LLVM_VERSION(3, 6)
  auto personality_func = GetPersonalityFunction();
  lifted_func->setPersonalityFn(personality_func);
#endif

  for (const auto &entry : cfg_func->eh_frame) {
    if (entry->lp_ea) {
      CreateLandingPad(ctx, entry.get());
    }
  }
}

static void LiftFuncRestoredRegs(TranslationContext &ctx,
                                 llvm::BasicBlock *block, bool force = false);

// Lift an indirect jump into a switch instruction.
static void LiftIndirectJump(TranslationContext &ctx, llvm::BasicBlock *block,
                             const remill::Instruction &inst) {

  auto exit_point = GetLiftedToNativeExitPoint(kExitPointJump);
  auto fallback = DevirtualizeIndirectFlow(ctx, exit_point);

  std::unordered_map<uint64_t, llvm::BasicBlock *> block_map;

  if (ctx.cfg_block) {
    for (auto target_ea : ctx.cfg_block->successor_eas) {
      block_map.emplace(target_ea, GetOrCreateBlock(ctx, target_ea, true));
    }
  }

  // If we have no targets, then a reasonable target turns out to be the
  // next program counter (if we assume that it's a jump table.).
  if (block_map.empty()) {
    block_map.emplace(inst.next_pc, GetOrCreateBlock(ctx, inst.next_pc));
  }

  // Build up a set of all reachable blocks that were known at disassembly
  // time so that we can find blocks that have no predecessors.
  std::unordered_set<uint64_t> succ_eas;
  succ_eas.insert(ctx.cfg_func->ea);
  for (auto cfg_block : ctx.cfg_func->blocks) {
    succ_eas.insert(cfg_block->successor_eas.begin(),
                    cfg_block->successor_eas.end());
  }

  // We'll augment our block map to also target unreachable blocks, just in
  // case our disassembly failed to find some of the targets.
  for (auto cfg_block : ctx.cfg_func->blocks) {
    const auto block_ea = cfg_block->ea;
    if (block_map.count(block_ea)) {
      continue;

    } else if (!succ_eas.count(block_ea)) {
      LOG(WARNING) << "Adding block " << std::hex << block_ea
                   << " with no predecessors as additional target of the "
                   << " indirect jump at " << inst.pc << std::dec;
      block_map.emplace(block_ea, GetOrCreateBlock(ctx, block_ea, true));

    // This block is referenced by data, so it also makes a good jump table
    // target.
    } else if (cfg_block->is_referenced_by_data &&
               block_ea != ctx.cfg_func->ea) {
      LOG(WARNING) << "Adding block " << std::hex << block_ea
                   << " referenced by data as additional target of the "
                   << " indirect jump at " << inst.pc << std::dec;
      block_map.emplace(block_ea, GetOrCreateBlock(ctx, block_ea, true));
    }
  }

  // We have no jump table information, so assume that it's an indirect tail
  // call, so just go native.
  if (block_map.empty()) {
    LOG(INFO) << "Indirect jump at " << std::hex << inst.pc << std::dec
              << " looks like a thunk; falling back to "
              << fallback->getName().str();
    remill::AddTerminatingTailCall(block, fallback);
    return;
  }

  // Create a "default" fall-back block for the switch. The idea here is that
  // the xrefs might have been lifted to "block addresses" in the lifted
  // `.text` section.
  auto fallback_block1 =
      llvm::BasicBlock::Create(*gContext, "", block->getParent());

  // Create a "default" fall-back block for the switch.
  auto fallback_block2 =
      llvm::BasicBlock::Create(*gContext, "", block->getParent());

  auto num_blocks = static_cast<unsigned>(block_map.size());
  auto switch_index = LoadProgramCounter(ctx, block);

  if (ctx.cfg_inst && ctx.cfg_inst->offset_table) {
    LOG(INFO) << "Indirect jump at " << std::hex << ctx.cfg_inst->ea
              << " is a jump through an offset table with offset " << std::hex
              << ctx.cfg_inst->offset_table->target_ea << std::dec;

    llvm::IRBuilder<> ir(block);
    switch_index = ir.CreateAdd(
        ir.CreateSub(switch_index,
                     LiftXrefInCode(ctx.cfg_inst->offset_table->target_ea)),
        llvm::ConstantInt::get(gWordType,
                               ctx.cfg_inst->offset_table->target_ea));

    //    // TODO(pag): Keep???
    //    remill::StoreProgramCounter(block, switch_index);
  }

  // Put the `switch` into its own block. This makes handling indirect jumps
  // with delay slots easier, because then we can treat them as direct jumps
  // to the switch block.
  auto switch_block =
      llvm::BasicBlock::Create(*gContext, "", block->getParent());
  auto switch_inst = llvm::SwitchInst::Create(switch_index, fallback_block1,
                                              num_blocks, switch_block);

  LOG(INFO) << "Indirect jump at " << std::hex << inst.pc << " has " << std::dec
            << num_blocks << " targets";

  // Add the cases.
  std::vector<uint64_t> fallback_block_eas;
  std::vector<uint64_t> fallback_funcs;

  auto any_are_64_bit = false;

  for (auto [ea, block] : block_map) {
    if (ea != static_cast<uint32_t>(ea)) {
      any_are_64_bit = true;
    }
    if (ctx.cfg_module->TryGetFunction(ea)) {
      fallback_funcs.push_back(ea);
    } else {
      fallback_block_eas.push_back(ea);
    }

    switch_inst->addCase(llvm::ConstantInt::get(gWordType, ea, false), block);
  }

  llvm::BranchInst::Create(switch_block, block);

  const auto i32_type = llvm::Type::getInt32Ty(*gContext);

  if (!fallback_block_eas.empty()) {
    std::sort(fallback_block_eas.begin(), fallback_block_eas.end());
    const auto max_ea = fallback_block_eas.back();

    auto lifted_max_ea = LiftXrefInCode(max_ea);
    llvm::Value *block_offset =
        llvm::BinaryOperator::Create(llvm::Instruction::Sub, lifted_max_ea,
                                     switch_index, "", fallback_block1);

    // The block addresses will be 64-bit values, but the lifted xrefs in the
    // jump table may actually be 64-bit xrefs, casted down to 32 bits, so we're
    // going to deal with truncated values to hopefully make things work.
    if (gArch->address_size == 64 && !any_are_64_bit) {
      block_offset =
          llvm::TruncInst::Create(llvm::Instruction::Trunc, block_offset,
                                  i32_type, "", fallback_block1);
      block_offset =
          llvm::ZExtInst::Create(llvm::Instruction::ZExt, block_offset,
                                 gWordType, "", fallback_block1);
    }

    // Fallback switch on lifted block addresses.
    switch_inst = llvm::SwitchInst::Create(block_offset, fallback_block2,
                                           num_blocks, fallback_block1);

    for (auto [ea, block] : block_map) {
      switch_inst->addCase(
          llvm::ConstantInt::get(gWordType, max_ea - ea, false), block);
    }
  } else {
    llvm::BranchInst::Create(fallback_block2, fallback_block1);
  }

  // If any of the jump targets are functions, then handle them with a sequence
  // of comparisons.
  while (!fallback_funcs.empty()) {
    auto target_func_ea = fallback_funcs.back();
    fallback_funcs.pop_back();

    auto func_addr = LiftXrefInCode(target_func_ea);

    // The function addresses will be 64-bit values, but the lifted xrefs in the
    // jump table may actually be 64-bit xrefs, casted down to 32 bits, so we're
    // going to deal with truncated values to hopefully make things work.
    if (gArch->address_size == 64 && !any_are_64_bit) {
      func_addr = llvm::ConstantExpr::getTrunc(func_addr, i32_type);
      func_addr = llvm::ConstantExpr::getZExt(func_addr, gWordType);
    }

    auto cmp =
        llvm::CmpInst::Create(llvm::Instruction::ICmp, llvm::CmpInst::ICMP_EQ,
                              switch_index, func_addr, "", fallback_block2);

    auto next_fallback =
        llvm::BasicBlock::Create(*gContext, "", block->getParent());

    llvm::BranchInst::Create(block_map[target_func_ea], next_fallback, cmp,
                             fallback_block2);

    fallback_block2 = next_fallback;
  }

  // This is useful for debugging, so that we can see what instruction did
  // the indirect jump.
  // remill::StoreProgramCounter(fallback_block2, ctx.inst.pc);

  auto mem_ptr = LiftSubFuncCall(ctx, fallback_block2, fallback);
  LiftFuncRestoredRegs(ctx, fallback_block2, true);  // In case of tail-call.
  (void) llvm::ReturnInst::Create(*gContext, mem_ptr, fallback_block2);
}

// Call instrumentation. These are useful for debugging.
static void Instrument(const TranslationContext &ctx, llvm::BasicBlock *block,
                       uint64_t inst_ea) {

  if (!FLAGS_trace_reg_values.empty()) {
    LiftSubFuncCall(ctx, block, GetValueTracer(), PCValueKind::kConcretePC,
                    inst_ea);
  }

  if (FLAGS_add_state_tracer) {
    LiftSubFuncCall(ctx, block, GetRegTracer(), PCValueKind::kConcretePC,
                    inst_ea);
  }

  if (FLAGS_add_breakpoints) {
    llvm::Value *args[1] = {LoadMemoryPointer(ctx, block)};
    auto call = llvm::CallInst::Create(GetBreakPoint(inst_ea), args, "", block);
    auto mem_ptr = LoadMemoryPointerRef(ctx, block);
    (void) new llvm::StoreInst(call, mem_ptr, block);
  }

  if (FLAGS_add_pc_tracer) {
    llvm::Value *args[1] = {llvm::ConstantInt::get(gWordType, inst_ea)};
    (void) llvm::CallInst::Create(GetPCTracer(), args, "", block);
  }
}

// Lift a decoded instruction into `block`. Returns `false` if there was a
// problem lifting.
static void LiftInstIntoBlock(TranslationContext &ctx,
                              remill::Instruction &inst,
                              llvm::BasicBlock *block, bool is_delayed) {
  const auto inst_ea = inst.pc;
  auto prev_cfg_inst = ctx.cfg_inst;
  if (is_delayed) {
    ctx.cfg_inst = ctx.cfg_module->TryGetInstruction(inst_ea);
  }

  Instrument(ctx, block, inst_ea);

  // Even when something isn't supported or is invalid, we still lift
  // a call to a semantic, e.g.`INVALID_INSTRUCTION`, so we really want
  // to treat instruction lifting as an operation that can't fail.
  (void) ctx.lifter->LiftIntoBlock(inst, block, is_delayed);

  // Annotate every un-annotated instruction in this function with the
  // program counter of the current instruction.
  if (FLAGS_legacy_mode) {
    legacy::AnnotateInsts(ctx.lifted_func, inst_ea);
  }

  ctx.cfg_inst = prev_cfg_inst;
}

static std::unordered_map<llvm::Type *, llvm::Function *> gTypeToRestorer;

// Get a type-specific register restorer.
static llvm::Function *GetRestorer(llvm::Type *type) {
  auto &func = gTypeToRestorer[type];
  if (func) {
    return func;
  }

  std::stringstream ss;
  ss << "__remill_restore." << remill::LLVMThingToString(type);
  const auto name = ss.str();
  func = gModule->getFunction(name);
  if (func) {
    return func;
  }

  llvm::Type *param_types[] = {type, type};
  func = llvm::Function::Create(
      llvm::FunctionType::get(type, param_types, false),
      llvm::GlobalValue::ExternalLinkage, name, gModule.get());

  // Tell LLVM that this function doesn't access memory; this improves LLVM's
  // ability to optimize around this function.
  func->addFnAttr(llvm::Attribute::ReadNone);

  return func;
}

static std::unordered_map<llvm::Type *, llvm::Constant *> gTypeToKiller;

// Get a type-specific register killer.
static llvm::Constant *GetKiller(llvm::Type *type) {
  auto &gc = gTypeToKiller[type];
  if (gc) {
    return gc;
  }

  auto gv = gModule->getGlobalVariable("__remill_kill");
  if (!gv) {
    gv = new llvm::GlobalVariable(*gModule, type, false,
                                  llvm::GlobalValue::ExternalLinkage, nullptr,
                                  "__remill_kill");
  }

  gc = llvm::ConstantExpr::getPtrToInt(gv, type);
  return gc;
}


//static std::unordered_map<llvm::Type *, llvm::Function *> gTypeToSavingKiller;
//
//// Get a type-specific register killer that lets us still store the right
//// value to the register.
//static llvm::Constant *GetSavingKiller(llvm::Type *type) {
//  auto &killer = gTypeToSavingKiller[type];
//  if (killer) {
//    return killer;
//  }
//
//  std::stringstream ss;
//  ss << "__remill_saving_kill_" << std::hex
//     << reinterpret_cast<uintptr_t>(type);
//  const auto name = ss.str();
//
//  killer = gModule->getFunction(name);
//  if (!killer) {
//    llvm::Type *param_types[] = {type};
//    killer = llvm::Function::Create(
//        llvm::FunctionType::get(type, param_types, false),
//        llvm::GlobalValue::ExternalLinkage, name, gModule.get());
//
//  }
//
//  killer->addFnAttr(llvm::Attribute::ReadNone);
//
//  return killer;
//}

// Save and restore registers around the body of a function.
void SaveAndRestoreFunctionPreservedRegs(TranslationContext &ctx,
                                         llvm::BasicBlock *entry_block,
                                         llvm::BasicBlock *inst_block,
                                         llvm::Value *state_ptr,
                                         uint64_t end_ea,
                                         const NativePreservedRegisters &regs) {

  llvm::IRBuilder<> ir(entry_block);
  llvm::IRBuilder<> restore_ir(inst_block);
  for (const auto &reg_name : regs.reg_names) {
    if (!gArch->RegisterByName(reg_name)) {
      continue;
    }

    // If it's a register in the state structure, then we're going to use
    // a special preservation pattern. The idea is this:
    //
    // We will say:
    //    %reg = load %reg_ptr
    //    ...
    //    %latest_val = load %reg_ptr
    //    %restore_val = call __mcsema_restore.i64(%reg, %latest_val)
    //    store %restore_val, %reg_ptr
    //
    // If after optimization, we end up with the following then we can
    // eliminate the `store` entirely.
    //    %restore_val = call __mcsema_restore.i64(%reg, %reg)
    //
    // However, if after optimization the two parameters don't match, then
    // we need to preserve the restore, and we'll replace all uses of
    // `%restore_val` with `%reg`.
    const auto reg_ptr =
        ctx.lifter->LoadRegAddress(entry_block, ctx.state_ptr, reg_name);
    const auto reg = ir.CreateLoad(reg_ptr);
    const auto reg_latest = restore_ir.CreateLoad(reg_ptr);
    llvm::Value *restorer_args[] = {reg, reg_latest};

    // NOTE(pag): We use volatile stores so that LLVM doesn't eliminate them
    //            if we're saving/restoring an `alloca`d object.
    const auto restorer = GetRestorer(reg->getType());
    restore_ir.CreateStore(restore_ir.CreateCall(restorer, restorer_args),
                           reg_ptr, true /* IsVolatile */);

    // Restored ones should be inserted in reverse order.
    restore_ir.SetInsertPoint(reg_latest);
  }
}

static void LiftDelayedInstIntoBlock(TranslationContext &ctx,
                                     llvm::BasicBlock *block,
                                     bool on_taken_path) {
  if (ctx.delayed_inst.IsValid() &&
      gArch->NextInstructionIsDelayed(ctx.inst, ctx.delayed_inst,
                                      on_taken_path)) {
    LiftInstIntoBlock(ctx, ctx.delayed_inst, block, true /* is_delayed */);
  }
}

static void LiftSavedRegs(TranslationContext &ctx, llvm::BasicBlock *block) {

  llvm::IRBuilder<> ir(block);
  DCHECK(ctx.inst.IsFunctionCall());
  ctx.cfg_module->ForEachInstructionPreservedRegister(
      ctx.inst.pc, [=, &ir, &ctx](const std::string &reg_name) {
        if (const auto reg = gArch->RegisterByName(reg_name); reg) {
          const auto reg_ptr =
              ctx.lifter->LoadRegAddress(block, ctx.state_ptr, reg_name);
          const auto reg_val = ir.CreateLoad(reg_ptr);
          ctx.preserved_regs.emplace_back(reg_ptr, reg_val);
        }
      });
}

static void LiftRestoredRegs(TranslationContext &ctx, llvm::BasicBlock *block) {
  if (ctx.preserved_regs.empty()) {
    return;
  }
  std::reverse(ctx.preserved_regs.begin(), ctx.preserved_regs.end());
  llvm::IRBuilder<> ir(block);
  for (auto [reg_ptr, saved_val] : ctx.preserved_regs) {
    ir.CreateStore(saved_val, reg_ptr);
  }
  ctx.preserved_regs.clear();
}

void LiftFuncRestoredRegs(TranslationContext &ctx, llvm::BasicBlock *block,
                          bool force) {
  auto regs_it = ctx.func_preserved_regs.find(ctx.inst.pc);
  if (regs_it == ctx.func_preserved_regs.end()) {
    if (!force || ctx.func_preserved_regs.empty()) {
      return;
    } else {
      regs_it = ctx.func_preserved_regs.begin();
    }
  }

  const auto func = block->getParent();
  const auto state_ptr = LoadStatePointer(ctx, block);
  SaveAndRestoreFunctionPreservedRegs(ctx, &(func->getEntryBlock()), block,
                                      state_ptr, ctx.inst.pc,
                                      *(regs_it->second));
}

static void KillPCAndNextPC(TranslationContext &ctx, llvm::BasicBlock *block) {
  const auto pc_ref = LoadProgramCounterRef(ctx, block);
  const auto npc_ref = LoadNextProgramCounterRef(ctx, block);
  llvm::IRBuilder<> ir(block);
  const auto kill_value = GetKiller(gWordType);
  ir.CreateStore(kill_value, pc_ref);
  ir.CreateStore(kill_value, npc_ref);
}

static void RevivePCAndNextPC(TranslationContext &ctx, llvm::BasicBlock *block,
                              uint64_t pc) {
  const auto pc_ref = LoadProgramCounterRef(ctx, block);
  const auto npc_ref = LoadNextProgramCounterRef(ctx, block);
  llvm::IRBuilder<> ir(block);
  const auto revive_value = LiftXrefInCode(pc);
  ir.CreateStore(revive_value, pc_ref);
  ir.CreateStore(revive_value, npc_ref);
}

static void LiftKilledRegs(TranslationContext &ctx, llvm::BasicBlock *block) {
  llvm::IRBuilder<> ir(block);
  ctx.cfg_module->ForEachInstructionKilledRegister(
      ctx.inst.pc, [=, &ir, &ctx](const std::string &reg_name) {
        const auto reg_ptr =
            ctx.lifter->LoadRegAddress(block, ctx.state_ptr, reg_name);
        if (!reg_ptr) {
          return;
        }
        auto reg_type = reg_ptr->getType()->getPointerElementType();
        ir.CreateStore(GetKiller(reg_type), reg_ptr);
      });
}

// Get the basic block within this function associated with a specific program
// counter.
llvm::BasicBlock *GetOrCreateBlock(TranslationContext &ctx, uint64_t pc,
                                   bool force_as_block) {
  auto &block = ctx.ea_to_block[pc];
  if (block) {
    return block;
  }

  std::stringstream ss;
  ss << "inst_" << std::hex << pc;
  block = llvm::BasicBlock::Create(*gContext, ss.str(), ctx.lifted_func);

  // Missed an instruction?! This can happen when IDA merges two instructions
  // into one larger synthetic instruction. This might also be a tail-call.
  ctx.work_list.emplace_back(pc, force_as_block, ctx.inst.pc);

  return block;
}

// Figure out the fall-through return address for a function call. There are
// annoying SPARC-isms to deal with due to their awful ABI choices.
static uint64_t FunctionReturnAddress(TranslationContext &ctx) {
  static const bool is_sparc = gArch->IsSPARC32() || gArch->IsSPARC64();
  const auto pc = ctx.inst.branch_not_taken_pc;
  if (!is_sparc) {
    return pc;
  }

  auto byte = ctx.cfg_module->FindByte(pc);
  if (!byte.IsExecutable()) {
    return pc;
  }

  uint8_t bytes[4] = {};

  for (auto i = 0u; i < 4u && byte && byte.IsExecutable();
       ++i, byte = ctx.cfg_module->FindNextByte(byte)) {
    auto maybe_val = byte.Value();
    if (remill::IsError(maybe_val)) {
      (void) remill::GetErrorString(maybe_val);  // Drop the error.
    } else {
      bytes[i] = remill::GetReference(maybe_val);
    }
  }

  union Format0a {
    uint32_t flat;
    struct {
      uint32_t imm22 : 22;
      uint32_t op2 : 3;
      uint32_t rd : 5;
      uint32_t op : 2;
    } u __attribute__((packed));
  } __attribute__((packed)) enc = {};
  static_assert(sizeof(Format0a) == 4, " ");

  enc.flat |= bytes[0];
  enc.flat <<= 8;
  enc.flat |= bytes[1];
  enc.flat <<= 8;
  enc.flat |= bytes[2];
  enc.flat <<= 8;
  enc.flat |= bytes[3];

  // This looks like an `unimp <imm22>` instruction, where the `imm22` encodes
  // the size of the value to return. See "Programming Note" in v8 manual, B.31,
  // p 137.
  if (!enc.u.op && !enc.u.op2) {
    LOG(INFO) << "Found structure return of size " << enc.u.imm22 << " to "
              << std::hex << pc << " at " << ctx.inst.pc << std::dec;
    return pc + 4u;

  } else {
    return pc;
  }
}

// Lift a decoded block into a function.
static void LiftInstIntoFunction(TranslationContext &ctx,
                                 llvm::BasicBlock *block,
                                 const remill::IntrinsicTable &intrinsics) {
  LiftInstIntoBlock(ctx, ctx.inst, block, false /* is_delayed */);

  // We might need to lift another instruction and execute it in the delay
  // slot. `cont` contains enough info to redirect control flow after we've
  // dealt with the lifting of the delayed instruction.
  if (ctx.delayed_inst.IsValid()) {
    ctx.delayed_inst.Reset();
  }

  if (gArch->MayHaveDelaySlot(ctx.inst)) {
    if (!TryDecodeInstruction(ctx, ctx.inst.delayed_pc, true) ||
        !ctx.delayed_inst.IsValid()) {
      LOG(ERROR) << "Unable to decode or use delayed instruction at "
                 << std::hex << ctx.inst.delayed_pc << std::dec << " of "
                 << ctx.inst.Serialize();
    }
  }

  ctx.preserved_regs.clear();

  switch (ctx.inst.category) {
    case remill::Instruction::kCategoryInvalid:
      remill::AddTerminatingTailCall(block, intrinsics.error);
      break;

    case remill::Instruction::kCategoryError:
      LiftDelayedInstIntoBlock(ctx, block, true);
      LiftFuncRestoredRegs(ctx, block, true);
      KillPCAndNextPC(ctx, block);
      LiftKilledRegs(ctx, block);
      remill::AddTerminatingTailCall(block, intrinsics.error);
      break;

    case remill::Instruction::kCategoryNormal: {
      CHECK(!ctx.delayed_inst.IsValid());
      llvm::BranchInst::Create(GetOrCreateBlock(ctx, ctx.inst.next_pc), block);
      break;
    }

    case remill::Instruction::kCategoryNoOp: {
      CHECK(!ctx.delayed_inst.IsValid());
      auto next_func = ctx.cfg_module->TryGetFunction(ctx.inst.next_pc);
      if (next_func && (next_func->ea != ctx.cfg_func->ea)) {
        LiftFuncRestoredRegs(ctx, block);
        KillPCAndNextPC(ctx, block);
        LiftKilledRegs(ctx, block);
        llvm::ReturnInst::Create(*gContext, LoadMemoryPointer(ctx, block),
                                 block);
      } else {
        llvm::BranchInst::Create(GetOrCreateBlock(ctx, ctx.inst.next_pc),
                                 block);
      }
      break;
    }

    case remill::Instruction::kCategoryDirectJump:
      LiftDelayedInstIntoBlock(ctx, block, true);
      KillPCAndNextPC(ctx, block);
      llvm::BranchInst::Create(GetOrCreateBlock(ctx, ctx.inst.branch_taken_pc),
                               block);
      break;

    case remill::Instruction::kCategoryIndirectJump:
      LiftDelayedInstIntoBlock(ctx, block, true);
      LiftIndirectJump(ctx, block, ctx.inst);
      break;

    case remill::Instruction::kCategoryDirectFunctionCall: {
      LiftDelayedInstIntoBlock(ctx, block, true);

      if (auto [targ_cfg_func, targ_func] =
              FindFunction(ctx, ctx.inst.branch_taken_pc, intrinsics);
          targ_cfg_func && targ_func) {

        const auto ret_pc = FunctionReturnAddress(ctx);

        if (!ctx.cfg_inst || !ctx.cfg_inst->lp_ea) {
          LiftSavedRegs(ctx, block);
          KillPCAndNextPC(ctx, block);
          LiftKilledRegs(ctx, block);
          LiftSubFuncCall(ctx, block, targ_func, PCValueKind::kUndefPC);
          LiftRestoredRegs(ctx, block);
          RevivePCAndNextPC(ctx, block, ret_pc);
          llvm::BranchInst::Create(GetOrCreateBlock(ctx, ret_pc), block);

        // TODO(pag): The save/restore optimization will produce unexpected
        //            lifts when exceptions are involved.
        //
        // TODO(pag): Revive the program counter / next program counter after
        //            the invoke inst.
        } else {
          auto exception_block = ctx.lp_to_block[ctx.cfg_inst->lp_ea];
          auto normal_block = GetOrCreateBlock(ctx, ret_pc);
          KillPCAndNextPC(ctx, block);
          LiftKilledRegs(ctx, block);
          InlineSubFuncInvoke(ctx, block, targ_func, normal_block,
                              exception_block, ctx.cfg_func,
                              PCValueKind::kUndefPC);
        }

      // Treat a `call +5` as not actually needing to call out to a
      // new subroutine.
      } else if (ctx.inst.branch_taken_pc == ctx.inst.next_pc) {
        LOG(WARNING) << "Not adding a subroutine self-call at " << std::hex
                     << ctx.inst.pc << std::dec;
        llvm::BranchInst::Create(
            GetOrCreateBlock(ctx, ctx.inst.branch_taken_pc), block);

      // This is a legitimate call to a function that seems to have been missed.
      } else {
        LOG(ERROR)
            << "Cannot find target of instruction at " << std::hex
            << ctx.inst.pc << "; the static target " << std::hex
            << ctx.inst.branch_taken_pc
            << " is not associated with a lifted subroutine, and it does not "
            << "have a known call target" << std::dec;

        LiftSavedRegs(ctx, block);
        KillPCAndNextPC(ctx, block);
        LiftKilledRegs(ctx, block);
        LiftSubFuncCall(ctx, block, intrinsics.function_call,
                        PCValueKind::kConcretePC, ctx.inst.branch_taken_pc);
        LiftRestoredRegs(ctx, block);
        RevivePCAndNextPC(ctx, block, ctx.inst.branch_not_taken_pc);
        llvm::BranchInst::Create(
            GetOrCreateBlock(ctx, ctx.inst.branch_not_taken_pc), block);
      }
      break;
    }

    case remill::Instruction::kCategoryIndirectFunctionCall: {
      const auto fallback_func =
          GetLiftedToNativeExitPoint(kExitPointFunctionCall);
      const auto target_func = DevirtualizeIndirectFlow(ctx, fallback_func);

      LOG_IF(ERROR, ctx.cfg_inst && ctx.cfg_inst->lp_ea)
          << "Not treating call from " << std::hex << ctx.inst.pc
          << " as invoke" << std::dec;

      LiftDelayedInstIntoBlock(ctx, block, true);

      const auto ret_pc = FunctionReturnAddress(ctx);

      if (!ctx.cfg_inst || !ctx.cfg_inst->lp_ea) {
        LiftSavedRegs(ctx, block);
        LiftKilledRegs(ctx, block);
        if (fallback_func == target_func) {
          LiftSubFuncCall(ctx, block, target_func);
        } else {
          KillPCAndNextPC(ctx, block);
          LiftSubFuncCall(ctx, block, target_func, PCValueKind::kUndefPC);
        }
        LiftRestoredRegs(ctx, block);
        RevivePCAndNextPC(ctx, block, ret_pc);
        llvm::BranchInst::Create(GetOrCreateBlock(ctx, ret_pc), block);

      // TODO(pag): Revive the PC and next PC after the invoke.
      } else {
        auto exception_block = ctx.lp_to_block[ctx.cfg_inst->lp_ea];
        auto normal_block = GetOrCreateBlock(ctx, ret_pc);

        if (fallback_func == target_func) {
          InlineSubFuncInvoke(ctx, block, target_func, normal_block,
                              exception_block, ctx.cfg_func);

        } else {
          KillPCAndNextPC(ctx, block);
          LiftKilledRegs(ctx, block);
          InlineSubFuncInvoke(ctx, block, target_func, normal_block,
                              exception_block, ctx.cfg_func,
                              PCValueKind::kUndefPC);
        }
      }
      break;
    }

    case remill::Instruction::kCategoryFunctionReturn:
      LiftDelayedInstIntoBlock(ctx, block, true);
      LiftFuncRestoredRegs(ctx, block);
      KillPCAndNextPC(ctx, block);
      LiftKilledRegs(ctx, block);
      llvm::ReturnInst::Create(*gContext, LoadMemoryPointer(ctx, block), block);
      break;

    case remill::Instruction::kCategoryConditionalBranch:
    case remill::Instruction::kCategoryConditionalAsyncHyperCall: {
      const auto cond = remill::LoadBranchTaken(block);
      const auto taken_block =
          llvm::BasicBlock::Create(*gContext, "", ctx.lifted_func);
      const auto not_taken_block =
          llvm::BasicBlock::Create(*gContext, "", ctx.lifted_func);
      llvm::BranchInst::Create(taken_block, not_taken_block, cond, block);
      LiftDelayedInstIntoBlock(ctx, taken_block, true);
      LiftDelayedInstIntoBlock(ctx, not_taken_block, false);
      llvm::BranchInst::Create(GetOrCreateBlock(ctx, ctx.inst.branch_taken_pc),
                               taken_block);
      llvm::BranchInst::Create(
          GetOrCreateBlock(ctx, ctx.inst.branch_not_taken_pc), not_taken_block);
      break;
    }

    case remill::Instruction::kCategoryAsyncHyperCall:
      LiftDelayedInstIntoBlock(ctx, block, true);
      LiftSubFuncCall(ctx, block, intrinsics.async_hyper_call);
      llvm::BranchInst::Create(GetOrCreateBlock(ctx, ctx.inst.branch_taken_pc),
                               block);
      break;
  }
}

static llvm::Function *LiftFunction(const NativeModule *cfg_module,
                                    const NativeFunction *cfg_func,
                                    const remill::IntrinsicTable &intrinsics) {

  CHECK(!cfg_func->is_external)
      << "Should not lift external function " << cfg_func->name;

  const auto lifted_func = cfg_func->lifted_function;
  CHECK(nullptr != lifted_func)
      << "Could not find declaration for " << cfg_func->lifted_name;

  // This can happen due to deduplication of functions during the
  // CFG decoding process. In practice, though, that only really
  // affects externals.
  if (!lifted_func->empty()) {
    LOG(WARNING) << "Asking to re-insert function: " << cfg_func->lifted_name
                 << "; returning current function instead";
    return lifted_func;
  }

  remill::CloneBlockFunctionInto(lifted_func);

  lifted_func->removeFnAttr(llvm::Attribute::NoReturn);
  lifted_func->removeFnAttr(llvm::Attribute::NoUnwind);
  lifted_func->setVisibility(llvm::GlobalValue::DefaultVisibility);
  lifted_func->setLinkage(llvm::GlobalValue::ExternalLinkage);

  if ((gArch->IsSPARC64() &&
       cfg_func->name.find("__sparc_get_pc_thunk") == 0) ||
      (gArch->IsX86() && cfg_func->name.find("__x86.get_pc_thunk") == 0)) {
    lifted_func->removeFnAttr(llvm::Attribute::NoInline);
    lifted_func->addFnAttr(llvm::Attribute::AlwaysInline);
    lifted_func->addFnAttr(llvm::Attribute::InlineHint);
  } else {
    lifted_func->removeFnAttr(llvm::Attribute::AlwaysInline);
    lifted_func->removeFnAttr(llvm::Attribute::InlineHint);
    lifted_func->addFnAttr(llvm::Attribute::NoInline);
  }

  if (FLAGS_stack_protector) {
    lifted_func->addFnAttr(llvm::Attribute::StackProtectReq);
  }

  TranslationContext ctx;
  InstructionLifter lifter(&intrinsics, ctx);

  ctx.lifter = &lifter;
  ctx.cfg_module = cfg_module;
  ctx.cfg_func = cfg_func;
  ctx.cfg_block = nullptr;
  ctx.cfg_inst = nullptr;
  ctx.lifted_func = lifted_func;
  ctx.state_ptr = remill::NthArgument(lifted_func, remill::kStatePointerArgNum);

  std::unordered_set<uint64_t> referenced_blocks;
  referenced_blocks.insert(cfg_func->ea);

  // Collect the known set of blocks into a work list, and add basic blocks
  // for each of them.
  if (cfg_func->blocks.empty()) {
    LOG(WARNING) << "Function " << cfg_func->lifted_name << " is empty!";
    GetOrCreateBlock(ctx, cfg_func->ea, true /* force */);

  } else {
    for (const auto cfg_block : cfg_func->blocks) {
      const auto block_ea = cfg_block->ea;
      (void) GetOrCreateBlock(ctx, block_ea, true /* force */);
    }
  }

  std::sort(ctx.work_list.begin(), ctx.work_list.end(),
            [](std::tuple<uint64_t, bool, uint64_t> a,
               std::tuple<uint64_t, bool, uint64_t> b) {
              return std::get<0>(a) < std::get<0>(b);
            });
  auto unique_it = std::unique(ctx.work_list.begin(), ctx.work_list.end());
  ctx.work_list.erase(unique_it, ctx.work_list.end());

  // Lift the landing pad if there are exception frames recovered.
  LiftExceptionFrameLP(ctx, cfg_func);

  const auto entry_block = &(lifted_func->front());

  if (FLAGS_add_func_state_tracer) {
    LiftSubFuncCall(ctx, entry_block, GetRegTracer());
  }

  const auto next_pc_ref = LoadNextProgramCounterRef(ctx, entry_block);
  const auto pc_ref = LoadProgramCounterRef(ctx, entry_block);
  const auto pc = LiftXrefInCode(cfg_func->ea);
  llvm::IRBuilder<> ir(entry_block);
  ir.CreateStore(pc, next_pc_ref);
  ir.CreateStore(pc, pc_ref);

  // Used for exception handling.
  ctx.stack_ptr_var =
      ir.CreateAlloca(llvm::Type::getInt64Ty(*gContext),
                      llvm::ConstantInt::get(gWordType, 1), "stack_ptr_var");

  ctx.frame_ptr_var =
      ir.CreateAlloca(llvm::Type::getInt64Ty(*gContext),
                      llvm::ConstantInt::get(gWordType, 1), "frame_ptr_var");

  // Preserve registers at a function granularity.
  cfg_module->ForEachRangePreservedRegister(
      cfg_func->ea,
      [=, &ctx](uint64_t end_ea, const NativePreservedRegisters &regs) {
        ctx.func_preserved_regs.emplace(end_ea, &regs);
      });

  // Reverse the work list so that we can treat it like a stack.
  std::reverse(ctx.work_list.begin(), ctx.work_list.end());

  // Process the instructions in reverse order, filling up their basic blocks.
  while (!ctx.work_list.empty()) {
    auto [inst_ea, force_as_block, from_ea] = ctx.work_list.back();
    ctx.work_list.pop_back();

    auto block = ctx.ea_to_block[inst_ea];
    CHECK_NOTNULL(block);

    if (!block->empty()) {
      continue;  // Already handled.
    }

    // First, try to see if it's actually related to another function. This is
    // equivalent to a tail-call in the original code.
    if (inst_ea != cfg_func->ea) {
      if (auto tail_called_func = cfg_module->TryGetFunction(inst_ea);
          tail_called_func && !force_as_block) {
        LOG(WARNING) << "Adding tail-call from " << std::hex << inst_ea
                     << " in function " << ctx.cfg_func->lifted_name << " to "
                     << tail_called_func->lifted_name << " from " << from_ea
                     << std::dec;

        auto mem_ptr = LiftSubFuncCall(
            ctx, block,
            CallableLiftedFunc(tail_called_func, intrinsics.function_call));
        LiftFuncRestoredRegs(ctx, block, true);
        (void) llvm::ReturnInst::Create(*gContext, mem_ptr, block);
        continue;
      }
    }

    if (!TryDecodeInstruction(ctx, inst_ea, false)) {
      if (from_ea) {
        LOG(ERROR) << "Could not decode instruction at " << std::hex << inst_ea
                   << " reachable from instruction " << from_ea
                   << " in function " << cfg_func->name << " at "
                   << cfg_func->ea << std::dec << ": " << ctx.inst.Serialize();
      } else {
        LOG(ERROR) << "Could not decode instruction at " << std::hex << inst_ea
                   << " in function " << cfg_func->name << " at "
                   << cfg_func->ea << std::dec << ": " << ctx.inst.Serialize();
      }
      remill::AddTerminatingTailCall(block, intrinsics.error);

    } else if (!ctx.inst.IsValid() || ctx.inst.IsError()) {
      remill::AddTerminatingTailCall(block, intrinsics.error);

    } else {
      ctx.cfg_block = ctx.cfg_module->TryGetBlock(inst_ea, ctx.cfg_block);
      ctx.cfg_inst = ctx.cfg_module->TryGetInstruction(inst_ea);
      LiftInstIntoFunction(ctx, block, intrinsics);
    }
  }

  // Connect the function to the first block.
  llvm::BranchInst::Create(ctx.ea_to_block[cfg_func->ea], entry_block);

  // NOTE(pag): We may have unreachable blocks, especially on architectures
  //            like where instructions in delay slots might not be reachable
  //            on their own.

  const auto mut_cfg_func = const_cast<NativeFunction *>(cfg_func);
  mut_cfg_func->blocks.clear();
  mut_cfg_func->eh_frame.clear();

  return lifted_func;
}

using Calls_t = std::vector<llvm::CallSite>;

static bool ShouldInline(const llvm::CallSite &cs) {
  if (!cs) {
    return false;
  }
  auto callee = cs.getCalledFunction();
  return callee &&
         remill::HasOriginType<remill::Semantics, remill::ExtWrapper>(callee);
}

static Calls_t InlinableCalls(llvm::Function &func) {
  Calls_t out;
  for (auto &bb : func) {
    for (auto &inst : bb) {
      auto cs = llvm::CallSite(&inst);
      if (ShouldInline(cs)) {
        out.push_back(std::move(cs));
      }
    }
  }
  return out;
}

static void InlineCalls(llvm::Function &func) {
  for (auto &cs : InlinableCalls(func)) {
    if (auto call = llvm::dyn_cast<llvm::CallInst>(cs.getInstruction())) {
      llvm::InlineFunctionInfo info;
      llvm::InlineFunction(call, info);
    }
  }
}

}  // namespace

// Declare the lifted functions. This is a separate step from defining
// functions because it's important that all possible code- and data-cross
// references are resolved before any data or instructions can use
// those references.
void DeclareLiftedFunctions(const NativeModule *cfg_module) {

  for (auto [ea, cfg_func] : cfg_module->ea_to_func) {
    (void) ea;

    if (cfg_func->is_external) {
      continue;
    }

    const auto &func_name = cfg_func->lifted_name;
    auto lifted_func = gModule->getFunction(func_name);

    if (!lifted_func) {
      lifted_func = remill::DeclareLiftedFunction(gModule.get(), func_name);

      // make local functions 'static'
      LOG(INFO) << "Inserted function: " << func_name;

    } else {
      LOG(INFO) << "Already inserted function: " << func_name << ", skipping.";
    }

    // All lifted functions are marked as external so they aren't optimized
    // away.
    lifted_func->setLinkage(llvm::GlobalValue::ExternalLinkage);
    cfg_func->lifted_function = lifted_func;
  }
}

// Lift the blocks and instructions into the function. Some minor optimization
// passes are applied to clean out any unneeded register variables brought
// in from cloning the `__remill_basic_block` function.
bool DefineLiftedFunctions(const NativeModule *cfg_module) {
  llvm::legacy::FunctionPassManager func_pass_manager(gModule.get());
  func_pass_manager.add(llvm::createCFGSimplificationPass());
  func_pass_manager.add(llvm::createPromoteMemoryToRegisterPass());
  func_pass_manager.add(llvm::createReassociatePass());
  func_pass_manager.add(llvm::createDeadStoreEliminationPass());
  func_pass_manager.add(llvm::createDeadCodeEliminationPass());
  func_pass_manager.doInitialization();

  remill::IntrinsicTable intrinsics(gModule);

  // Make sure that `callable_lifted_function` is defined for each function.
  for (auto [ea, cfg_func] : cfg_module->ea_to_func) {
    (void) ea;

    DCHECK_EQ(cfg_func, cfg_func->Get());

    if (cfg_func->is_external) {
      (void) GetLiftedToNativeExitPoint(cfg_func);

    } else {

      // For local calls between lifted functions, prefer our state-passing
      // version, even if we generate an entry point
      cfg_func->callable_lifted_function = cfg_func->lifted_function;
    }
  }

  for (auto [ea, cfg_func] : cfg_module->ea_to_func) {
    (void) ea;

    if (cfg_func->is_external) {
      continue;
    }

    auto lifted_func = LiftFunction(cfg_module, cfg_func, intrinsics);
    if (!lifted_func) {
      LOG(ERROR) << "Could not lift function: " << cfg_func->name << " at "
                 << std::hex << cfg_func->ea << " into "
                 << cfg_func->lifted_name << std::dec;
      return false;
    }

    // Unfortunately there can be `return_twice` attribute on some external functions
    // (setjmp). This prevents llvm from inlining the `ext_` wrapper, but it is mandatory
    // that the actual call is behind a wrapper (due to how it is implemented).
    if (false && FLAGS_explicit_args) {
      InlineCalls(*lifted_func);
    }

    func_pass_manager.run(*lifted_func);
  }

  func_pass_manager.doFinalization();

  return true;
}

}  // namespace mcsema
