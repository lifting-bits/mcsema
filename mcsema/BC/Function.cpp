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

#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Type.h>

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Compat/ScalarTransforms.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Lifter.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Callback.h"
#include "mcsema/BC/Function.h"
#include "mcsema/BC/Instruction.h"
#include "mcsema/BC/Legacy.h"
#include "mcsema/BC/Lift.h"
#include "mcsema/BC/Optimize.h"
#include "mcsema/BC/Segment.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

DECLARE_bool(legacy_mode);

DEFINE_bool(add_reg_tracer, false,
            "Add a debug function that prints out the register state before "
            "each lifted instruction execution.");

DEFINE_bool(add_breakpoints, false,
            "Add 'breakpoint' functions between every lifted instruction. This "
            "allows one to set a breakpoint, in the lifted code, just before a "
            "specific lifted instruction is executed. This is a debugging aid.");

DEFINE_bool(check_pc_at_breakpoints, false,
            "Check whether or not the emulated program counter is correct at "
            "each injected 'breakpoint' function. This is a debugging aid.");

DEFINE_string(exception_personality_func, "__gxx_personality_v0",
              "Add a personality function for lifting exception handling "
              "routine. Assigned __gxx_personality_v0 as default for c++ ABTs.");

DEFINE_bool(stack_protector, false, "Annotate functions so that if the bitcode "
            "is compiled with -fstack-protector-all then the stack protection "
            "guards will be added.");

namespace mcsema {

namespace {

// Get the personality function of exception handling ABIs.
// For libstdc++ it will be reference to `__gxx_personality_v0`
static llvm::Function *GetPersonalityFunction(void) {
  const auto &personality_func_name = FLAGS_exception_personality_func;

  // The personality function is lifted as global variable. Check and erase the
  // variable before declaring it as the function.
  if (auto personality_func = gModule->getGlobalVariable(personality_func_name)) {
    personality_func->eraseFromParent();
  }

  auto personality_func = gModule->getFunction(personality_func_name);
  if (personality_func == nullptr) {
    personality_func = llvm::Function::Create(
        llvm::FunctionType::get(llvm::Type::getInt32Ty(*gContext), true),
        llvm::Function::ExternalLinkage, personality_func_name, gModule);
  }
  return personality_func;
}

static llvm::Function *GetRegTracer(void) {
  auto reg_tracer = gModule->getFunction("__mcsema_reg_tracer");
  if (!reg_tracer) {
    reg_tracer = llvm::Function::Create(
        LiftedFunctionType(), llvm::GlobalValue::ExternalLinkage,
        "__mcsema_reg_tracer", gModule);
  }
  return reg_tracer;
}

static llvm::Function *GetBreakPoint(uint64_t pc) {
  std::stringstream ss;
  ss << "breakpoint_" << std::hex << pc;

  auto func_name = ss.str();
  auto func = gModule->getFunction(func_name);
  if (func) {
    return func;
  }

  func = llvm::Function::Create(
      LiftedFunctionType(), llvm::GlobalValue::ExternalLinkage,
      func_name, gModule);

  // Make sure to keep this function around (along with `ExternalLinkage`).
  func->removeFnAttr(llvm::Attribute::ReadNone);
  func->addFnAttr(llvm::Attribute::OptimizeNone);
  func->addFnAttr(llvm::Attribute::NoInline);

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 7)
  func->addFnAttr(llvm::Attribute::ReadOnly);
#else
  func->addFnAttr(llvm::Attribute::ArgMemOnly);
#endif

  auto state_ptr = remill::NthArgument(func, remill::kStatePointerArgNum);
  auto state_ptr_type = state_ptr->getType();

  llvm::IRBuilder<> ir(llvm::BasicBlock::Create(*gContext, "", func));

  if (FLAGS_check_pc_at_breakpoints) {
    auto trap = llvm::Intrinsic::getDeclaration(gModule, llvm::Intrinsic::trap);
    auto are_eq = ir.CreateICmpEQ(
        remill::NthArgument(func, remill::kPCArgNum),
        llvm::ConstantInt::get(gWordType, pc));

    auto not_eq_bb = llvm::BasicBlock::Create(*gContext, "", func);
    auto eq_bb = llvm::BasicBlock::Create(*gContext, "", func);
    ir.CreateCondBr(are_eq, eq_bb, not_eq_bb);

    ir.SetInsertPoint(not_eq_bb);
    ir.CreateCall(trap);
    ir.CreateUnreachable();

    ir.SetInsertPoint(eq_bb);
  }

  // Basically some empty inline assembly that tells the compiler not to
  // optimize away the `state` pointer before each `breakpoint_XXX` function.
  auto asm_func_type = llvm::FunctionType::get(
      llvm::Type::getVoidTy(*gContext), state_ptr_type, false);

  auto asm_func = llvm::InlineAsm::get(
      asm_func_type, "", "*m,~{dirflag},~{fpsr},~{flags}", true);

  ir.CreateCall(asm_func, state_ptr);
  ir.CreateRet(remill::NthArgument(func, remill::kMemoryPointerArgNum));
  return func;
}

// Tries to get the lifted function beginning at `pc`.
static llvm::Function *GetLiftedFunction(const NativeModule *cfg_module,
                                         uint64_t pc) {
  if (auto cfg_func = cfg_module->TryGetFunction(pc)) {
    return gModule->getFunction(cfg_func->lifted_name);
  }
  return nullptr;
}

// The exception handling prologue function clears the stack and set the
// stack and frame pointer correctly before jumping to the handler routine.
static llvm::Function *GetExceptionHandlerPrologue(void) {
  auto dword_type = llvm::Type::getInt32Ty(*gContext);
  auto exception_handler = gModule->getFunction("__mcsema_exception_ret");
  if (exception_handler == nullptr) {
    llvm::Type* args_type[] = {
        gWordType,
        gWordType,
        dword_type
    };
    auto func_type = llvm::FunctionType::get(
        llvm::Type::getVoidTy(*gContext), args_type, false);
    exception_handler = llvm::Function::Create(
        func_type, llvm::Function::ExternalWeakLinkage,
        "__mcsema_exception_ret", gModule);
  }
  return exception_handler;
}

// `__mcsema_get_type_index` function returns the RDX register holding
// the exception type index. It also saves the RAX register state.
static llvm::Function *GetExceptionTypeIndex(void) {
  auto get_index_func = gModule->getFunction("__mcsema_get_type_index");
  if (!get_index_func) {
    get_index_func = llvm::Function::Create(
        llvm::FunctionType::get(gWordType, false),
        llvm::GlobalValue::ExternalWeakLinkage,
        "__mcsema_get_type_index", gModule);
  }

  return get_index_func;
}

// Add a call to another function, and then update the memory pointer with the
// result of the function.
static void InlineSubFuncCall(llvm::BasicBlock *block,
                              llvm::Function *sub) {
  auto call = llvm::CallInst::Create(
      sub, remill::LiftedFunctionArgs(block), "", block);
  call->setCallingConv(sub->getCallingConv());
  auto mem_ptr = remill::LoadMemoryPointerRef(block);
  (void) new llvm::StoreInst(call, mem_ptr, block);
}

// Add a invoke to another function and then update the memory pointer with the
// result of the function. It also needs to stash the stack and frame pointer which
// can be restored before handling the exception handler.
static void InlineSubFuncInvoke(llvm::BasicBlock *block,
                                llvm::Function *sub, llvm::BasicBlock *if_normal,
                                llvm::BasicBlock *if_exception,
                                const NativeFunction *cfg_func) {
  llvm::IRBuilder <> ir(block);
  auto get_sp_func = gModule->getFunction("__mcsema_get_stack_pointer");
  if (!get_sp_func) {
    get_sp_func = llvm::Function::Create(
        llvm::FunctionType::get(gWordType, false),
        llvm::GlobalValue::ExternalLinkage,
        "__mcsema_get_stack_pointer", gModule);
  }
  auto sp_var = ir.CreateCall(get_sp_func);
  ir.CreateStore(sp_var, cfg_func->stack_ptr_var);

  auto get_bp_func = gModule->getFunction("__mcsema_get_frame_pointer");
  if (!get_bp_func) {
    get_bp_func = llvm::Function::Create(
        llvm::FunctionType::get(gWordType, false),
        llvm::GlobalValue::ExternalLinkage,
        "__mcsema_get_frame_pointer", gModule);
  }
  auto bp_var = ir.CreateCall(get_bp_func);
  ir.CreateStore(bp_var, cfg_func->frame_ptr_var);
  auto invoke = ir.CreateInvoke(
      sub, if_normal, if_exception, remill::LiftedFunctionArgs(block), "");
  invoke->setCallingConv(sub->getCallingConv());
}

// Find an external function associated with this indirect jump.
static llvm::Function *DevirtualizeIndirectFlow(
    const NativeFunction *cfg_func, llvm::Function *fallback) {
  if (cfg_func->is_external) {
    return GetLiftedToNativeExitPoint(cfg_func);
  } else if (auto func = gModule->getFunction(cfg_func->lifted_name)) {
    return func;
  } else {
    return fallback;
  }
}

// Find an external function associated with this indirect jump.
static llvm::Function *DevirtualizeIndirectFlow(
    TranslationContext &ctx, llvm::Function *fallback) {
  if (ctx.cfg_inst->flow) {
    if (auto cfg_func = ctx.cfg_inst->flow->func) {
      return DevirtualizeIndirectFlow(cfg_func, fallback);
    }
  }

  // This is a bit sketchy, but let's assume that it might be a thunk
  // (e.g in the PLT). If so, then we're doing a jump through a loaded
  // pointer, where the pointer will be fixed up with an external EA,
  // i.e. there should be a cross-reference entry at the target pointing
  // to the destination function.
  if (auto mem = ctx.cfg_inst->mem) {
    auto seg = mem->target_segment;

    // In case there is a variable that has some default value, e.g. can
    // be recognized both as xref and var on the same ea
    // However later it can be changed to different value, so we can't
    // devirtualize it (issue #474)
    if (!mem->segment->is_read_only) {
      return fallback;
    }
    auto target_ea_ptr_ea = mem->target_ea;
    auto entry_it = seg->entries.find(target_ea_ptr_ea);
    if (entry_it != seg->entries.end()) {
      const NativeSegment::Entry &entry = entry_it->second;
      if (entry.xref && entry.xref->func) {
        return DevirtualizeIndirectFlow(entry.xref->func, fallback);
      }
    }
  }

  return fallback;
}

// Try to find a function. We start by assuming that `target_pc` is an
// absolute address for the function. This is usually the case for direct
// function calls internal to a binary. However, if the function is actually
// an external function then we try to return the external version of the
// function.
static llvm::Function *FindFunction(TranslationContext &ctx,
                                    uint64_t target_pc) {

  const NativeFunction *cfg_func = nullptr;
  if (ctx.cfg_inst->flow) {
    cfg_func = ctx.cfg_inst->flow->func;
    if (cfg_func && cfg_func->is_external) {
      return GetLiftedToNativeExitPoint(cfg_func);
    }
  }

  auto func = GetLiftedFunction(ctx.cfg_module, target_pc);
  if (func) {
    return func;
  }

  if (cfg_func) {
    auto lifted_func = gModule->getFunction(cfg_func->lifted_name);
    if (lifted_func) {
      LOG(WARNING)
          << "Cannot find target of instruction at " << std::hex
          << ctx.cfg_inst->ea << "; the static target "
          << std::hex << target_pc << " is not associated with a lifted"
          << " subroutine, but is associated with the function at " << std::hex
          << cfg_func->ea << " in the CFG." << std::dec;

      return lifted_func;
    }
  }

  LOG(ERROR)
      << "Cannot find target of instruction at " << std::hex
      << ctx.cfg_inst->ea << "; the static target "
      << std::hex << target_pc << " is not associated with a lifted"
      << " subroutine, and it does not have a known call target."
      << std::dec;

  return ctx.lifter->intrinsics->error;
}

// Get the basic block within this function associated with a specific program
// counter.
static llvm::BasicBlock *GetOrCreateBlock(TranslationContext &ctx,
                                          uint64_t pc) {
  auto &block = ctx.ea_to_block[pc];
  if (!block) {
    std::stringstream ss;
    ss << "block_" << std::hex << pc;
    block = llvm::BasicBlock::Create(*gContext, ss.str(), ctx.lifted_func);

    // First, try to see if it's actually related to another function. This is
    // equivalent to a tail-call in the original code.
    if (auto tail_called_func = FindFunction(ctx, pc)) {
      LOG_IF(ERROR, !ctx.cfg_block->successor_eas.count(pc))
          << "Adding missing block " << std::hex << pc << " in function "
          << ctx.cfg_func->lifted_name << " as a tail call to "
          << tail_called_func->getName().str() << std::dec;

      remill::AddTerminatingTailCall(block, tail_called_func);

    // Terminate the block with an unreachable inst.
    } else {
      LOG(ERROR)
          << "Adding missing block " << std::hex << pc << " in function "
          << ctx.cfg_func->lifted_name << " as a jump to the error intrinsic."
          << std::dec;

      remill::AddTerminatingTailCall(
          block, ctx.lifter->intrinsics->missing_block);
    }
  }
  return block;
}

// Create a landing pad basic block.
static void CreateLandingPad(TranslationContext &ctx,
                             struct NativeExceptionFrame *eh_entry) {
  std::stringstream ss;

  auto dword_type = llvm::Type::getInt32Ty(*gContext);
  // `__mcsema_exception_ret` argument list
  std::vector<llvm::Value *> args(3);
  auto is_catch = (eh_entry->action_index != 0);
  ss << "landingpad_" << std::hex << eh_entry->lp_ea;
  auto landing_bb = llvm::BasicBlock::Create(
      *gContext, ss.str(), ctx.lifted_func);

  std::vector<llvm::Type *> elem_types = {
      llvm::Type::getInt8PtrTy(*gContext), dword_type};

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

  if(is_catch) {
    std::stringstream g_variable_name_ss;
    std::vector<llvm::Constant *>array_value_const;
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
    auto array_type = llvm::ArrayType::get(
        dword_type, eh_entry->type_var.size() + 1);

    if (!gModule->getOrInsertGlobal(g_variable_name, array_type)) {
      LOG_IF(ERROR, 1)
          << "Can't create the global variable " << g_variable_name
          << " for the landing pad at" << std::hex << eh_entry->lp_ea
          << std::dec;
    }

    auto gvar_landingpad = gModule->getGlobalVariable(g_variable_name);
    gvar_landingpad->setLinkage(llvm::GlobalValue::ExternalLinkage);

    // Set the dummy value for index `0`
    array_value_const.push_back(llvm::ConstantInt::get(dword_type, 0));

    std::reverse(array_value_const.begin(), array_value_const.end());
    llvm::ArrayRef<llvm::Constant *> array_value(array_value_const);
    llvm::Constant* const_array = llvm::ConstantArray::get(
        array_type, array_value);
    gvar_landingpad->setInitializer(const_array);
    auto type_index_value2 = ir.CreateCall(GetExceptionTypeIndex());
    auto type_index_value1 = llvm::ConstantInt::get(dword_type, 0);

    // Get the type index from the original binary and set the `RDX` register
    std::vector<llvm::Value *> array_index_vec;
    array_index_vec.push_back(type_index_value1);
    array_index_vec.push_back(type_index_value2);

    auto var_value = ir.CreateGEP(gvar_landingpad, array_index_vec);


#if LLVM_VERSION_NUMBER > LLVM_VERSION(3, 6)
    args[0] = ir.CreateLoad(gWordType, ctx.cfg_func->stack_ptr_var);
    args[1] = ir.CreateLoad(gWordType, ctx.cfg_func->frame_ptr_var);
    args[2] = ir.CreateLoad(dword_type, var_value);
#else
    args[0] = ir.CreateLoad(ctx.cfg_func->stack_ptr_var, true);
    args[1] = ir.CreateLoad(ctx.cfg_func->frame_ptr_var, true);
    args[2] = ir.CreateLoad(var_value, true);
#endif

  } else {
    auto type_index_value = ir.CreateCall(GetExceptionTypeIndex());
#if LLVM_VERSION_NUMBER > LLVM_VERSION(3, 6)
    args[0] = ir.CreateLoad(gWordType, ctx.cfg_func->stack_ptr_var);
    args[1] = ir.CreateLoad(gWordType, ctx.cfg_func->frame_ptr_var);
    args[2] = ir.CreateTruncOrBitCast(type_index_value, dword_type);
#else
    args[0] = ir.CreateLoad(ctx.cfg_func->stack_ptr_var, true);
    args[1] = ir.CreateLoad(ctx.cfg_func->frame_ptr_var, true);
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
  if (cfg_func->eh_frame.size() > 0) {
    auto lifted_func = gModule->getFunction(cfg_func->lifted_name);
    lifted_func->addFnAttr(llvm::Attribute::UWTable);
    lifted_func->addFnAttr(llvm::Attribute::OptimizeNone);
    lifted_func->removeFnAttr(llvm::Attribute::NoUnwind);
#if LLVM_VERSION_NUMBER > LLVM_VERSION(3, 6)
    auto personality_func = GetPersonalityFunction();
    lifted_func->setPersonalityFn(personality_func);
#endif
  }

  for (auto &entry : cfg_func->eh_frame) {
    if (entry->lp_ea) {
      CreateLandingPad(ctx, entry);
    }
  }
}

// Lift both targets of a conditional branch into a branch in the bitcode,
// where each side of the branch tail-calls to the functions associated with
// the lifted blocks for those branch targets.
static void LiftConditionalBranch(TranslationContext &ctx,
                                  llvm::BasicBlock *source,
                                  remill::Instruction &inst) {
  auto block_true = GetOrCreateBlock(ctx, inst.branch_taken_pc);
  auto block_false = GetOrCreateBlock(ctx, inst.branch_not_taken_pc);
  llvm::IRBuilder<> cond_ir(source);
  cond_ir.CreateCondBr(
      remill::LoadBranchTaken(source),
      block_true,
      block_false);
}

// Lift an indirect jump into a switch instruction.
static void LiftIndirectJump(TranslationContext &ctx,
                             llvm::BasicBlock *block,
                             remill::Instruction &inst) {

  auto exit_point = GetLiftedToNativeExitPoint(kExitPointJump);
  auto fallback = DevirtualizeIndirectFlow(ctx, exit_point);

  std::unordered_map<uint64_t, llvm::BasicBlock *> block_map;
  for (auto target_ea : ctx.cfg_block->successor_eas) {
    block_map[target_ea] = GetOrCreateBlock(ctx, target_ea);
    fallback = ctx.lifter->intrinsics->missing_block;
  }

  if (exit_point == fallback) {

    // If we have no targets, then a reasonable target turns out to be the
    // next program counter (if we assume that it's a jump table.).
    if (block_map.empty()) {
      block_map[inst.next_pc] = GetOrCreateBlock(ctx, inst.next_pc);
    }

    // Build up a set of all reachable blocks that were known at disassembly
    // time so that we can find blocks that have no predecessors.
    std::unordered_set<uint64_t> succ_eas;
    succ_eas.insert(ctx.cfg_func->ea);
    for (auto block_entry : ctx.cfg_func->blocks) {
      auto cfg_block = block_entry.second;
      succ_eas.insert(cfg_block->successor_eas.begin(),
                      cfg_block->successor_eas.end());
    }

    // We'll augment our block map to also target unreachable blocks, just in
    // case our disassembly failed to find some of the targets.
    for (auto block_entry : ctx.cfg_func->blocks) {
      auto target_ea = block_entry.first;
      if (!succ_eas.count(target_ea)) {
        LOG(WARNING)
            << "Adding block " << std::hex << target_ea
            << " with no predecessors as additional target of the "
            << " indirect jump at " << inst.pc << std::dec;
        block_map[target_ea] = GetOrCreateBlock(ctx, target_ea);
      }
    }
  }

  // We have no jump table information, so assume that it's an indirect tail
  // call, so just go native.
  if (block_map.empty()) {
    LOG(INFO)
        << "Indirect jump at " << std::hex << inst.pc << std::dec
        << " looks like a thunk; falling back to " << fallback->getName().str();
    remill::AddTerminatingTailCall(block, fallback);
    return;
  }

  // Create a "default" fall-back block for the switch.
  auto fallback_block = llvm::BasicBlock::Create(
      *gContext, "", block->getParent());

  remill::AddTerminatingTailCall(fallback_block, fallback);

  auto num_blocks = static_cast<unsigned>(block_map.size());
  auto switch_index = remill::LoadProgramCounter(block);

  if (ctx.cfg_inst->offset_table) {
    LOG(INFO)
        << "Indirect jump at " << std::hex << ctx.cfg_inst->ea
        << " is a jump through an offset table with offset "
        << std::hex << ctx.cfg_inst->offset_table->target_ea << std::dec;

    llvm::IRBuilder<> ir(block);
    switch_index = ir.CreateAdd(
        ir.CreateSub(switch_index,
                     LiftEA(ctx.cfg_inst->offset_table->target_segment,
                            ctx.cfg_inst->offset_table->target_ea)),
        llvm::ConstantInt::get(
            gWordType, ctx.cfg_inst->offset_table->target_ea));

    remill::StoreProgramCounter(block, switch_index);
  }

  auto switch_inst = llvm::SwitchInst::Create(
      switch_index, fallback_block, num_blocks, block);

  LOG(INFO)
      << "Indirect jump at " << std::hex << inst.pc
      << " has " << std::dec << num_blocks << " targets";

  // Add the cases.
  for (auto ea_to_block : block_map) {
    switch_inst->addCase(
        llvm::ConstantInt::get(ctx.lifter->word_type, ea_to_block.first, false),
        ea_to_block.second);
  }
}

// Returns `true` if `instr` should end a basic block and if a terminator was
// added to end the block.
static bool TryLiftTerminator(TranslationContext &ctx,
                              llvm::BasicBlock *block,
                              remill::Instruction &inst) {
  switch (inst.category) {
    case remill::Instruction::kCategoryInvalid:
    case remill::Instruction::kCategoryError:
      remill::AddTerminatingTailCall(block, ctx.lifter->intrinsics->error);
      return true;

    case remill::Instruction::kCategoryNormal:
    case remill::Instruction::kCategoryNoOp:
      return false;

    case remill::Instruction::kCategoryDirectJump:
      llvm::BranchInst::Create(
          GetOrCreateBlock(ctx, inst.branch_taken_pc), block);
      return true;

    case remill::Instruction::kCategoryIndirectJump:
      LiftIndirectJump(ctx, block, inst);
      return true;

    case remill::Instruction::kCategoryDirectFunctionCall:

      // Treat a `call +5` as not actually needing to call out to a
      // new subroutine.
      if (inst.branch_taken_pc != inst.next_pc) {
        auto targ_func = FindFunction(ctx, inst.branch_taken_pc);
        DLOG(INFO)
            << "Function " << ctx.lifted_func->getName().str()
            << " calls " << targ_func->getName().str()
            << " at " << std::hex << inst.pc << std::dec;
        if (!ctx.cfg_inst->lp_ea) {
          InlineSubFuncCall(block, targ_func);
        } else {
          auto exception_block = ctx.lp_to_block[ctx.cfg_inst->lp_ea];
          auto normal_block = GetOrCreateBlock(ctx, inst.next_pc);
          ctx.ea_to_block[inst.next_pc] = normal_block;
          InlineSubFuncInvoke(block, targ_func, normal_block, exception_block,
                              ctx.cfg_func);
          return true;
        }

      } else {
        LOG(WARNING)
            << "Not adding a subroutine self-call at "
            << std::hex << inst.pc << std::dec;
      }
      return false;

    case remill::Instruction::kCategoryIndirectFunctionCall:
      InlineSubFuncCall(
          block,
          DevirtualizeIndirectFlow(
              ctx, GetLiftedToNativeExitPoint(kExitPointFunctionCall)));
      return false;

    case remill::Instruction::kCategoryFunctionReturn:
      llvm::ReturnInst::Create(
          *gContext, remill::LoadMemoryPointer(block), block);
      return true;

    case remill::Instruction::kCategoryConditionalBranch:
    case remill::Instruction::kCategoryConditionalAsyncHyperCall:
      LiftConditionalBranch(ctx, block, inst);
      return true;

    case remill::Instruction::kCategoryAsyncHyperCall:
      InlineSubFuncCall(block, ctx.lifter->intrinsics->async_hyper_call);
      remill::StoreProgramCounter(block, inst.next_pc);
      return false;
  }
  return false;
}

// Lift a decoded instruction into `block`.
static bool LiftInstIntoBlock(TranslationContext &ctx,
                              llvm::BasicBlock *block,
                              bool is_last) {
  remill::Instruction inst;

  auto inst_addr = ctx.cfg_inst->ea;
  auto &bytes = ctx.cfg_inst->bytes;

  if (FLAGS_legacy_mode) {
    remill::StoreProgramCounter(block, inst_addr);
  }

  if (!gArch->DecodeInstruction(inst_addr, bytes, inst)) {
    LOG(ERROR)
        << "Unable to decode instruction " << inst.Serialize()
        << " at " << std::hex << inst_addr << std::dec;

    remill::AddTerminatingTailCall(block, ctx.lifter->intrinsics->error);
    return false;
  }

  DLOG_IF(WARNING, bytes.size() != inst.NumBytes())
      << "Size of decoded instruction at " << std::hex << inst_addr
      << " (" << std::dec << inst.NumBytes()
      << ") doesn't match input instruction size ("
      << bytes.size() << ").";

  if (FLAGS_add_reg_tracer) {
    InlineSubFuncCall(block, GetRegTracer());
  }

  if (FLAGS_add_breakpoints) {
    InlineSubFuncCall(block, GetBreakPoint(inst_addr));
  }

  ctx.lifter->LiftIntoBlock(inst, block);

  auto ret = true;
  if (TryLiftTerminator(ctx, block, inst)) {
    if (!is_last) {
      LOG(ERROR)
          << "Ending block early at " << std::hex << inst_addr;
      ret = false;
    }
  }

  // Annotate every un-annotated instruction in this function with the
  // program counter of the current instruction.
  if (FLAGS_legacy_mode) {
    legacy::AnnotateInsts(ctx.lifted_func, inst_addr);
  }

  return ret;
}

// Lift a decoded block into a function.
static void LiftBlockIntoFunction(TranslationContext &ctx) {
  auto block_name = ctx.cfg_block->lifted_name;
  auto block_pc = ctx.cfg_block->ea;
  auto block = ctx.ea_to_block[block_pc];

  ctx.cfg_inst = nullptr;

  // Lift each instruction into the block.
  size_t i = 0;
  const auto num_insts = ctx.cfg_block->instructions.size();
  for (auto cfg_inst : ctx.cfg_block->instructions) {
    ctx.cfg_inst = cfg_inst;
    auto is_last = (++i) >= num_insts;

    if (!LiftInstIntoBlock(ctx, block, is_last)) {
      return;
    }

    LOG_IF(WARNING, cfg_inst->does_not_return && !is_last)
        << "Instruction at " << std::hex << cfg_inst->ea
        << " has a local no-return, but is not the last instruction"
        << " in its block (" << std::hex << block_pc
        << "). Terminating anyway." << std::dec;
  }

  const auto &follows = ctx.cfg_block->successor_eas;
  if (!block->getTerminator()) {
    if (!ctx.cfg_inst || ctx.cfg_inst->does_not_return) {
      LOG_IF(ERROR, !ctx.cfg_inst)
          << "Block " << std::hex << block_pc << " in function "
          << ctx.cfg_func->ea << std::dec << " has no instructions; "
          << "this could be because of an incorrectly disassembled jump table.";

      remill::AddTerminatingTailCall(block, ctx.lifter->intrinsics->error);

    } else if (follows.size() == 1) {
      (void) llvm::BranchInst::Create(
          GetOrCreateBlock(ctx, *(follows.begin())), block);

    } else {
      LOG(ERROR)
          << "Block " << std::hex << block_pc << " has no terminator, and"
          << " instruction at " << std::hex << ctx.cfg_inst->ea
          << " is not a local no-return function call." << std::dec;

      remill::AddTerminatingTailCall(
          block, ctx.lifter->intrinsics->missing_block);
    }
  }
}

// Allocate storage of the stack variables that we're going to lift.
static void AllocStackVars(llvm::BasicBlock *bb,
                           const NativeFunction *cfg_func) {
  llvm::IRBuilder<> ir(bb);
  llvm::Value *array_size = nullptr;
  llvm::Type *array_type = nullptr;

  for (auto s : cfg_func->stack_vars) {
    switch(s->size){
      case 1:
      case 2:
      case 4:
      case 8:
        array_type = llvm::Type::getIntNTy(
            *gContext, static_cast<unsigned>(s->size * 8U));
        array_size = llvm::ConstantInt::get(gWordType, 1);
        break;

      default:
        array_type = llvm::Type::getInt8Ty(*gContext);
        array_size = llvm::ConstantInt::get(gWordType, s->size);
        break;
    }

    LOG(INFO)
        << "Inserting " << s->size << "-byte variable " << s->name
        << " into function" << cfg_func->name;

    // TODO(kumarak): Alignment of `alloca`s?
    s->llvm_var = ir.CreateAlloca(array_type, array_size, s->name);
  }

  cfg_func->stack_ptr_var = ir.CreateAlloca(
      llvm::Type::getInt64Ty(*gContext),
      llvm::ConstantInt::get(gWordType, 1), "stack_ptr_var");

  cfg_func->frame_ptr_var = ir.CreateAlloca(
      llvm::Type::getInt64Ty(*gContext),
      llvm::ConstantInt::get(gWordType, 1), "frame_ptr_var");
}

static llvm::Function *LiftFunction(
    const NativeModule *cfg_module, const NativeFunction *cfg_func) {

  CHECK(!cfg_func->is_external)
      << "Should not lift external function " << cfg_func->name;

  static std::unique_ptr<remill::IntrinsicTable> intrinsics;
  if (!intrinsics.get()) {
    intrinsics.reset(new remill::IntrinsicTable(gModule));
  }

  auto lifted_func = gModule->getFunction(cfg_func->lifted_name);
  CHECK(nullptr != lifted_func)
      << "Could not find declaration for " << cfg_func->lifted_name;
  cfg_func->function = lifted_func;

  // This can happen due to deduplication of functions during the
  // CFG decoding process. In practice, though, that only really
  // affects externals.
  if (!lifted_func->empty()) {
    LOG(WARNING)
        << "Asking to re-insert function: " << cfg_func->lifted_name
        << "; returning current function instead";
    return lifted_func;
  }

  if (cfg_func->blocks.empty()) {
    LOG(ERROR)
        << "Function " << cfg_func->lifted_name << " is empty!";
    remill::AddTerminatingTailCall(lifted_func, intrinsics->missing_block);
    return lifted_func;
  }

  remill::CloneBlockFunctionInto(lifted_func);

  lifted_func->removeFnAttr(llvm::Attribute::AlwaysInline);
  lifted_func->removeFnAttr(llvm::Attribute::InlineHint);
  lifted_func->removeFnAttr(llvm::Attribute::NoReturn);
  lifted_func->removeFnAttr(llvm::Attribute::NoUnwind);
  lifted_func->addFnAttr(llvm::Attribute::NoInline);
  lifted_func->setVisibility(llvm::GlobalValue::DefaultVisibility);

  if (FLAGS_stack_protector) {
    lifted_func->addFnAttr(llvm::Attribute::StackProtectReq);
  }

  TranslationContext ctx;
  std::unique_ptr<remill::InstructionLifter> lifter(
      new InstructionLifter(intrinsics.get(), ctx));

  ctx.lifter = lifter.get();
  ctx.cfg_module = cfg_module;
  ctx.cfg_func = cfg_func;
  ctx.cfg_block = nullptr;
  ctx.cfg_inst = nullptr;
  ctx.lifted_func = lifted_func;

  std::unordered_set<uint64_t> referenced_blocks;
  referenced_blocks.insert(cfg_func->ea);


  // Create basic blocks for each basic block in the original function.
  for (auto block_info : cfg_func->blocks) {
    auto cfg_block = block_info.second;
    ctx.ea_to_block[block_info.first] = llvm::BasicBlock::Create(
        *gContext, cfg_block->lifted_name, lifted_func);
  }

  // Allocate the stack variable recovered in the function
  auto entry_block = ctx.ea_to_block[cfg_func->ea];
  AllocStackVars(entry_block, cfg_func);

  // Lift the landing pad if there are exception frames recovered.
  LiftExceptionFrameLP(ctx, cfg_func);

  llvm::BranchInst::Create(ctx.ea_to_block[cfg_func->ea],
                           &(lifted_func->front()));

  for (auto block_info : cfg_func->blocks) {
    ctx.cfg_block = block_info.second;
    LiftBlockIntoFunction(ctx);
  }

  // Check the sanity of things.
  for (auto block_info : ctx.ea_to_block) {
    auto block = block_info.second;
    CHECK(block->getTerminator() != nullptr)
        << "Lifted block " << std::hex << block_info.first
        << " has no terminator!" << std::dec;
  }

  return lifted_func;
}

}  // namespace

// Declare the lifted functions. This is a separate step from defining
// functions because it's important that all possible code- and data-cross
// references are resolved before any data or instructions can use
// those references.
void DeclareLiftedFunctions(const NativeModule *cfg_module) {
  for (auto func : cfg_module->ea_to_func) {
    auto cfg_func = func.second->Get();
    if (cfg_func->is_external) {
      continue;
    }

    const auto &func_name = cfg_func->lifted_name;
    auto lifted_func = gModule->getFunction(func_name);

    if (!lifted_func) {
      lifted_func = remill::DeclareLiftedFunction(gModule, func_name);

      // make local functions 'static'
      LOG(INFO)
          << "Inserted function: " << func_name;

    } else {
      LOG(INFO)
          << "Already inserted function: " << func_name << ", skipping.";
    }
  }
}

// Lift the blocks and instructions into the function. Some minor optimization
// passes are applied to clean out any unneeded register variables brought
// in from cloning the `__remill_basic_block` function.
bool DefineLiftedFunctions(const NativeModule *cfg_module) {
  llvm::legacy::FunctionPassManager func_pass_manager(gModule);
  func_pass_manager.add(llvm::createCFGSimplificationPass());
  func_pass_manager.add(llvm::createPromoteMemoryToRegisterPass());
  func_pass_manager.add(llvm::createReassociatePass());
  func_pass_manager.add(llvm::createDeadStoreEliminationPass());
  func_pass_manager.add(llvm::createDeadCodeEliminationPass());
  func_pass_manager.doInitialization();

  for (auto &entry : cfg_module->ea_to_func) {
    auto cfg_func = reinterpret_cast<const NativeFunction *>(
        entry.second->Get());
    if (cfg_func->is_external) {
      continue;
    }

    auto lifted_func = LiftFunction(cfg_module, cfg_func);
    if (!lifted_func) {
      LOG(ERROR)
          << "Could lift function: " << cfg_func->name << " at "
          << std::hex << cfg_func->ea << " into " << cfg_func->lifted_name
          << std::dec;
      return false;
    }
    func_pass_manager.run(*lifted_func);
  }

  func_pass_manager.doFinalization();
  return true;
}

}  // namespace mcsema
