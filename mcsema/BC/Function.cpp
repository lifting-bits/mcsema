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

#include <llvm/Transforms/Scalar.h>

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/BC/ABI.h"
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

namespace mcsema {
namespace {

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
  func->addFnAttr(llvm::Attribute::OptimizeNone);
  func->addFnAttr(llvm::Attribute::NoInline);
  func->removeFnAttr(llvm::Attribute::ReadNone);

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
      llvm::Type::getVoidTy(*gContext), state_ptr_type);

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

// Find an external function associated with this indirect jump.
static llvm::Function *DevirtualizeIndirectFlow(
    TranslationContext &ctx, llvm::Function *fallback) {
  if (ctx.cfg_inst->flow) {
    if (auto cfg_func = ctx.cfg_inst->flow->func) {
      if (cfg_func->is_external) {
        return GetLiftedToNativeExitPoint(cfg_func);
      } else {
        return gModule->getFunction(cfg_func->lifted_name);
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

    // If we have no targets, then a reasonable target turns out to be the next
    // program counter.
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
        InlineSubFuncCall(block, targ_func);

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
  lifted_func->addFnAttr(llvm::Attribute::NoInline);
  lifted_func->setVisibility(llvm::GlobalValue::DefaultVisibility);

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
