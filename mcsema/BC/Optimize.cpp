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

#include "mcsema/BC/Optimize.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wswitch-enum"
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/ADT/Triple.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Utils/ValueMapper.h>
#pragma clang diagnostic pop

#include <anvill/Analyze.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Compat/GlobalValue.h>
#include <remill/BC/Compat/ScalarTransforms.h>
#include <remill/BC/Compat/TargetLibraryInfo.h>
#include <remill/BC/DeadStoreEliminator.h>
#include <remill/BC/Util.h>

#include <algorithm>
#include <limits>
#include <set>
#include <unordered_set>
#include <utility>
#include <vector>

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Optimize.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

DEFINE_bool(keep_memops, false,
            "Should the memory intrinsics be replaced or not?");

DEFINE_bool(check_for_lowmem_xrefs, false,
            "Check every constant, even those less than 4096, to see "
            "if they might be cross-reference targets. This might be "
            "reasonable to enable for PIC code, .o files, etc.");

DEFINE_bool(volatile_memops, false,
            "Mark all lowered loads/stores as volatile");

DEFINE_bool(local_state_pointer, false,
            "Use the state pointer passed by argument to all lifted functions."
            "Set local_state_pointer to false to disable it.");

DEFINE_bool(restore_all_on_unreachable, false,
            "Ensure that functions containing unreachable code end up "
            "restoring all saved registers on returning paths.");

DECLARE_bool(disable_aliases);

namespace mcsema {
namespace {

// Replace all uses of a specific intrinsic with an undefined value. We actually
// don't use LLVM's `undef` values because those can behave unpredictably
// across different LLVM versions with different optimization levels. Instead,
// we use a null value (zero, really).
static void ReplaceUndefIntrinsic(llvm::Function *function) {
  auto call_insts = remill::CallersOf(function);
  auto undef_val = llvm::Constant::getNullValue(function->getReturnType());
  for (auto call_inst : call_insts) {
    call_inst->replaceAllUsesWith(undef_val);
    call_inst->removeFromParent();
    delete call_inst;
  }
}

static void RemoveFunction(llvm::Function *func) {
  if (!func->hasNUsesOrMore(1)) {
    func->eraseFromParent();
  } else {
    auto ret_type = func->getReturnType();
    if (!ret_type->isVoidTy()) {
      func->replaceAllUsesWith(llvm::UndefValue::get(func->getType()));
      func->eraseFromParent();
    }
  }
}

static void RemoveFunction(const char *name) {
  if (auto func = gModule->getFunction(name)) {
    RemoveFunction(func);
  }
}

// Remove calls to the various undefined value intrinsics.
static void RemoveUndefFuncCalls(void) {
  llvm::Function *undef_funcs[] = {
      gModule->getFunction("__remill_undefined_8"),
      gModule->getFunction("__remill_undefined_16"),
      gModule->getFunction("__remill_undefined_32"),
      gModule->getFunction("__remill_undefined_64"),
      gModule->getFunction("__remill_undefined_f32"),
      gModule->getFunction("__remill_undefined_f64"),
  };

  for (auto undef_func : undef_funcs) {
    if (undef_func) {
      ReplaceUndefIntrinsic(undef_func);
      RemoveFunction(undef_func);
    }
  }
}

// Get a list of all ISELs.
static std::vector<llvm::GlobalVariable *> FindISELs(void) {
  std::vector<llvm::GlobalVariable *> isels;
  remill::ForEachISel(gModule.get(),
                      [&](llvm::GlobalVariable *isel, llvm::Function *) {
                        isels.push_back(isel);
                      });
  return isels;
}

// Remove the ISEL variables used for finding the instruction semantics.
static void PrivatizeISELs(std::vector<llvm::GlobalVariable *> &isels) {
  for (auto isel : isels) {
    isel->setInitializer(nullptr);
    isel->setExternallyInitialized(false);
    isel->setLinkage(llvm::GlobalValue::PrivateLinkage);

    if (!isel->hasNUsesOrMore(2)) {
      isel->eraseFromParent();
    }
  }
}

static void ReplaceBarrier(const char *name) {
  auto func = gModule->getFunction(name);
  if (!func) {
    return;
  }

  CHECK(func->isDeclaration())
      << "Cannot lower already implemented memory intrinsic " << name;

  auto callers = remill::CallersOf(func);
  for (auto call_inst : callers) {
    auto mem_ptr = call_inst->getArgOperand(0);
    call_inst->replaceAllUsesWith(mem_ptr);
    call_inst->eraseFromParent();
  }
}

static llvm::Value *FindPointer(llvm::IRBuilder<> &ir, llvm::Value *addr,
                                llvm::Type *elem_type, unsigned addr_space) {

  if (auto as_ptr_to_int = llvm::dyn_cast<llvm::PtrToIntOperator>(addr)) {
    if (!addr_space) {
      addr_space = as_ptr_to_int->getPointerAddressSpace();
    }
    auto curr = as_ptr_to_int->getPointerOperand();
    auto possible = FindPointer(ir, curr, elem_type, addr_space);
    return possible ? possible : curr;

  } else {
    return nullptr;
  }
}

unsigned GetPointerAddressSpace(llvm::Value *val, unsigned addr_space) {
  if (addr_space || !val) {
    return addr_space;
  }

  if (auto source_type = llvm::dyn_cast<llvm::PointerType>(val->getType())) {
    addr_space = source_type->getPointerAddressSpace();
    if (addr_space) {
      return addr_space;
    }
  }

  if (auto as_bc = llvm::dyn_cast<llvm::BitCastOperator>(val)) {
    return GetPointerAddressSpace(as_bc->getOperand(0), addr_space);

  } else if (auto as_pti = llvm::dyn_cast<llvm::PtrToIntOperator>(val)) {
    return GetPointerAddressSpace(as_pti->getOperand(0), addr_space);

  } else if (auto as_itp = llvm::dyn_cast<llvm::IntToPtrInst>(val)) {
    return GetPointerAddressSpace(as_itp->getOperand(0), addr_space);

  } else if (auto as_addr = llvm::dyn_cast<llvm::AddrSpaceCastInst>(val)) {
    return GetPointerAddressSpace(as_addr->getOperand(0), addr_space);

  } else {
    return addr_space;
  }
}

// Try to get an Value representing the address of `ea` as an entity, or return
// `nullptr`.
static llvm::Constant *GetAddress(const NativeModule *cfg_module, uint64_t ea) {
  if (auto cfg_var = cfg_module->TryGetVariable(ea); cfg_var) {
    return cfg_var->Address();

  } else if (auto cfg_func = cfg_module->TryGetFunction(ea); cfg_func) {
    return cfg_func->Address();

  } else if (auto cfg_seg = cfg_module->TryGetSegment(ea); cfg_seg) {
    return LiftXrefInData(cfg_seg, ea);

  // Look to see if `ea - 1` is the last byte of an existing segment or
  // variable, and if so, create a GEP that gets the address immediately
  // following the segment.
  //
  // NOTE(pag): In practice, we don't need to worry about segment padding
  //            here, as we expect that this pointer is used as an upper bound
  //            for some computation, and the referenced address is not
  //            actually mapped, so it's OK that it points into "the next
  //            element's" padding.
  } else {
    if (auto cfg_var = cfg_module->TryGetVariable(ea - 1); cfg_var) {
      auto i32_type = llvm::Type::getInt32Ty(*gContext);
      auto var = cfg_var->Pointer();
      auto var_type = var->getType()->getPointerElementType();
      auto ptr = llvm::ConstantExpr::getGetElementPtr(
          var_type, var, llvm::ConstantInt::get(i32_type, 1, false));
      return llvm::ConstantExpr::getPtrToInt(ptr, gWordType);

    } else if (auto cfg_seg = cfg_module->TryGetSegment(ea - 1); cfg_seg) {
      auto i32_type = llvm::Type::getInt32Ty(*gContext);
      auto seg_var = cfg_seg->Pointer();
      auto seg_type = seg_var->getType()->getPointerElementType();
      const auto ptr = llvm::ConstantExpr::getGetElementPtr(
          seg_type, seg_var, llvm::ConstantInt::get(i32_type, 1, false));
      return llvm::ConstantExpr::getPtrToInt(ptr, gWordType);
    }
  }

  return nullptr;
}

static llvm::Value *GetPointer(const NativeModule *cfg_module,
                               llvm::IRBuilder<> &ir, llvm::Value *addr,
                               llvm::Type *elem_type, unsigned addr_space);

static llvm::Value *GetIndexedPointer(const NativeModule *cfg_module,
                                      llvm::IRBuilder<> &ir, llvm::Value *lhs,
                                      llvm::Value *rhs, llvm::Type *dest_type,
                                      unsigned addr_space) {

  auto i32_ty = llvm::Type::getInt32Ty(*gContext);
  auto i8_ty = llvm::Type::getInt8Ty(*gContext);
  auto i8_ptr_ty = llvm::PointerType::get(i8_ty, addr_space);

  if (auto rhs_const = llvm::dyn_cast<llvm::ConstantInt>(rhs)) {
    const auto rhs_index = static_cast<int32_t>(rhs_const->getSExtValue());

    const auto &dl = gModule->getDataLayout();

    const auto [new_lhs, index] =
        remill::StripAndAccumulateConstantOffsets(dl, lhs);

    // It's possible that we will index into, but beyond, one global variable,
    // intending to get to another global.
    //
    // NOTE(pag): We use `getTypeStoreSize` of `global_type` so that we deal
    //            with the defined bytes, and not any implied alignment of
    //            globals lifted due to things like section alignment.
    if (auto lhs_global = llvm::dyn_cast<llvm::GlobalVariable>(new_lhs)) {

      if (cfg_module) {
        if (auto cfg_seg = cfg_module->TryGetSegment(lhs_global->getName())) {
          const auto real_ea =
              static_cast<uint64_t>(static_cast<int64_t>(cfg_seg->ea) + index);

          if (auto addr = GetAddress(cfg_module, real_ea)) {
            LOG_IF(WARNING, cfg_module->TryGetSegment(real_ea) != cfg_seg)
                << "Fixing cross-reference to " << std::hex << real_ea
                << std::dec << " that was misplaced into segment "
                << cfg_seg->name;

            return GetPointer(nullptr, ir, addr,
                              dest_type->getPointerElementType(), addr_space);

          } else {
            LOG(ERROR) << "Out-of-bounds reference to " << std::hex << real_ea
                       << std::dec << " tied to segment " << cfg_seg->name;
          }
        }
      }

      if (!index) {
        return ir.CreateBitCast(lhs_global, dest_type);
      }

      // It's a global variable not associated with a native segment, try to
      // index into it in a natural-ish way. We only apply this when the index
      // is positive.
      if (0 < index) {
        auto offset = static_cast<uint64_t>(index);
        return remill::BuildPointerToOffset(ir, lhs_global, offset, dest_type);
      }
    }

    auto lhs_elem_type = lhs->getType()->getPointerElementType();
    auto dest_elem_type = dest_type->getPointerElementType();

    const auto lhs_el_size = dl.getTypeAllocSize(lhs_elem_type);
    const auto dest_el_size = dl.getTypeAllocSize(dest_elem_type);

    llvm::Value *ptr = nullptr;

    // If either the source or destination element size is divisible by the
    // other then we might get lucky and be able to compute a pointer to the
    // destination with a single GEP.
    if (!(lhs_el_size % dest_el_size) || !(dest_el_size % lhs_el_size)) {

      if (0 > rhs_index) {
        const auto pos_rhs_index = static_cast<unsigned>(-rhs_index);
        if (!(pos_rhs_index % lhs_el_size)) {
          const auto scaled_index = static_cast<uint64_t>(
              rhs_index / static_cast<int64_t>(lhs_el_size));
          llvm::Value *indices[1] = {
              llvm::ConstantInt::get(i32_ty, scaled_index, true)};
          ptr = ir.CreateGEP(lhs_elem_type, lhs, indices);
        }
      } else {
        const auto pos_rhs_index = static_cast<unsigned>(rhs_index);
        if (!(pos_rhs_index % lhs_el_size)) {
          const auto scaled_index = static_cast<uint64_t>(
              rhs_index / static_cast<int64_t>(lhs_el_size));
          llvm::Value *indices[1] = {
              llvm::ConstantInt::get(i32_ty, scaled_index, false)};
          ptr = ir.CreateGEP(lhs_elem_type, lhs, indices);
        }
      }
    }

    // We got a GEP for the dest, now make sure it's the right type.
    if (ptr) {
      if (lhs->getType() == dest_type) {
        return ptr;
      } else {
        return ir.CreateBitCast(ptr, dest_type);
      }
    }
  }

  auto base = ir.CreateBitCast(lhs, i8_ptr_ty);
  llvm::Value *indices[1] = {ir.CreateTrunc(rhs, i32_ty)};
  auto gep = ir.CreateGEP(i8_ty, base, indices);
  return ir.CreateBitCast(gep, dest_type);
}

// Try to get a pointer for the address operand of a remill memory access
// intrinsic.
static llvm::Value *GetPointerFromInt(llvm::IRBuilder<> &ir, llvm::Value *addr,
                                      llvm::Type *elem_type,
                                      unsigned addr_space) {
  auto dest_type = llvm::PointerType::get(elem_type, addr_space);

  if (auto phi = llvm::dyn_cast<llvm::PHINode>(addr)) {
    const auto old_ipoint = &*(ir.GetInsertPoint());
    ir.SetInsertPoint(phi);

    const auto max = phi->getNumIncomingValues();
    const auto new_phi = ir.CreatePHI(dest_type, max);

    for (auto i = 0u; i < max; ++i) {
      auto val = phi->getIncomingValue(i);
      auto block = phi->getIncomingBlock(i);
      llvm::IRBuilder<> sub_ir(block->getTerminator());
      auto ptr = FindPointer(sub_ir, val, elem_type, addr_space);
      if (ptr) {
        if (ptr->getType() != dest_type) {
          ptr = sub_ir.CreateBitCast(ptr, dest_type);
        }
      } else {
        ptr = sub_ir.CreateIntToPtr(val, dest_type);
      }
      new_phi->addIncoming(ptr, block);
    }

    ir.SetInsertPoint(old_ipoint);

    return new_phi;

  } else {
    return ir.CreateIntToPtr(addr, dest_type);
  }
}

// Try to get a pointer for the address operand of a remill memory access
// intrinsic.
llvm::Value *GetPointer(const NativeModule *cfg_module, llvm::IRBuilder<> &ir,
                        llvm::Value *addr, llvm::Type *elem_type,
                        unsigned addr_space) {

  addr_space = GetPointerAddressSpace(addr, addr_space);
  const auto addr_type = addr->getType();
  auto dest_type = llvm::PointerType::get(elem_type, addr_space);

  // Handle this case first so that we don't return early on the `ptrtoint` that
  // may directly reach into the address parameter of the memory access
  // intrinsics.
  if (auto as_itp = llvm::dyn_cast<llvm::IntToPtrInst>(addr); as_itp) {
    llvm::IRBuilder<> sub_ir(as_itp);
    return GetPointer(cfg_module, sub_ir, as_itp->getOperand(0), elem_type,
                      addr_space);

  // It's a `ptrtoint`, but of the wrong type; lets go back and try to use
  // that pointer.
  } else if (auto as_pti = llvm::dyn_cast<llvm::PtrToIntOperator>(addr);
             as_pti) {
    return GetPointer(cfg_module, ir, as_pti->getPointerOperand(), elem_type,
                      addr_space);

  // We've found a pointer of the desired type; return :-D
  } else if (addr_type == dest_type) {
    return addr;

  // A missed cross-reference!
  } else if (auto ci = llvm::dyn_cast<llvm::ConstantInt>(addr); ci) {
    const auto ea = ci->getZExtValue();
    if (auto addr = GetAddress(cfg_module, ea); addr) {
      return GetPointer(cfg_module, ir, addr, elem_type, addr_space);

    } else {
      LOG(ERROR) << "Missed cross-reference target " << std::hex << ea
                 << " to pointer";
      return llvm::ConstantExpr::getIntToPtr(ci, dest_type);
    }

  // It's a constant expression, the one we're interested in is `inttoptr`
  // as we've already handled `ptrtoint` above.
  } else if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(addr); ce) {
    if (ce->getOpcode() == llvm::Instruction::IntToPtr) {
      return GetPointer(cfg_module, ir, ce->getOperand(0), elem_type,
                        addr_space);

    } else if (addr_type->isIntegerTy()) {
      return llvm::ConstantExpr::getIntToPtr(ce, dest_type);

    } else {
      CHECK(addr_type->isPointerTy());
      return llvm::ConstantExpr::getBitCast(ce, dest_type);
    }

  } else if (llvm::isa<llvm::GlobalValue>(addr)) {
    return ir.CreateBitCast(addr, dest_type);

  } else if (auto as_add = llvm::dyn_cast<llvm::AddOperator>(addr); as_add) {
    const auto lhs_op = as_add->getOperand(0);
    const auto rhs_op = as_add->getOperand(1);
    auto lhs = FindPointer(ir, lhs_op, elem_type, addr_space);
    auto rhs = FindPointer(ir, rhs_op, elem_type, addr_space);

    if (!lhs && !rhs) {

      auto lhs_inst = llvm::dyn_cast<llvm::Instruction>(lhs_op);
      auto lhs_const = llvm::dyn_cast<llvm::ConstantInt>(lhs_op);

      auto rhs_inst = llvm::dyn_cast<llvm::Instruction>(rhs_op);
      auto rhs_const = llvm::dyn_cast<llvm::ConstantInt>(rhs_op);

      // If we see something like the following:
      //
      //    %res = add %lhs_inst, <constant>
      //    %ptr = inttoptr %res
      //
      // Then go find/create a pointer for `%lhs_inst`, then generate a GEP
      // based off of that. This is to address a common pattern that we observe
      // with things like accesses through the stack pointer.
      if (lhs_inst && rhs_const && lhs_inst->hasNUsesOrMore(2)) {
        auto ipoint = lhs_inst->getNextNode();
        while (llvm::isa<llvm::PHINode>(ipoint)) {
          ipoint = ipoint->getNextNode();
        }
        llvm::IRBuilder<> sub_ir(ipoint);
        lhs = GetPointer(cfg_module, sub_ir, lhs_inst, elem_type, addr_space);

      } else if (lhs_const && rhs_inst && rhs_inst->hasNUsesOrMore(2)) {
        auto ipoint = rhs_inst->getNextNode();
        while (llvm::isa<llvm::PHINode>(ipoint)) {
          ipoint = ipoint->getNextNode();
        }
        llvm::IRBuilder<> sub_ir(ipoint);
        rhs = GetPointer(cfg_module, sub_ir, rhs_inst, elem_type, addr_space);

      } else {
        return GetPointerFromInt(ir, addr, elem_type, addr_space);
        return ir.CreateIntToPtr(addr, dest_type);
      }
    }

    addr_space = GetPointerAddressSpace(lhs, addr_space);
    addr_space = GetPointerAddressSpace(rhs, addr_space);
    dest_type = llvm::PointerType::get(elem_type, addr_space);

    if (lhs && rhs) {
      const auto bb = ir.GetInsertBlock();

      LOG(ERROR) << "Two pointers " << remill::LLVMThingToString(lhs) << " and "
                 << remill::LLVMThingToString(rhs) << " are added together "
                 << remill::LLVMThingToString(addr) << " in block "
                 << bb->getName().str() << " in function "
                 << bb->getParent()->getName().str();

      return ir.CreateIntToPtr(addr, dest_type);
    }

    if (rhs) {
      return GetIndexedPointer(cfg_module, ir, rhs, lhs_op, dest_type,
                               addr_space);

    } else {
      return GetIndexedPointer(cfg_module, ir, lhs, rhs_op, dest_type,
                               addr_space);
    }

  } else if (auto as_sub = llvm::dyn_cast<llvm::SubOperator>(addr); as_sub) {
    const auto lhs_op = as_sub->getOperand(0);
    const auto rhs_op = as_sub->getOperand(1);
    const auto rhs = llvm::dyn_cast<llvm::ConstantInt>(rhs_op);
    const auto lhs = FindPointer(ir, lhs_op, elem_type, addr_space);
    if (!lhs || !rhs) {
      return ir.CreateIntToPtr(addr, dest_type);

    } else {
      auto i32_ty = llvm::Type::getInt32Ty(*gContext);
      auto neg_index =
          static_cast<int64_t>(-static_cast<int32_t>(rhs->getZExtValue()));
      auto const_index = llvm::ConstantInt::get(
          i32_ty, static_cast<uint64_t>(neg_index), true);
      addr_space = GetPointerAddressSpace(lhs, addr_space);
      dest_type = llvm::PointerType::get(elem_type, addr_space);
      return GetIndexedPointer(cfg_module, ir, lhs, const_index, dest_type,
                               addr_space);
    }

  } else if (auto as_bc = llvm::dyn_cast<llvm::BitCastOperator>(addr); as_bc) {
    return GetPointer(cfg_module, ir, as_bc->getOperand(0), elem_type,
                      addr_space);

  // E.g. loading an address-sized integer register.
  } else if (addr_type->isIntegerTy()) {
    const auto bb = ir.GetInsertBlock();
    const auto addr_inst = &*ir.GetInsertPoint();

    // Go see if we can find multiple uses of `addr` in the same block, such
    // that each use converts `addr` to a pointer. If so, go and re-use those
    // `inttoptr` conversions instead of adding new ones.
    for (auto user : addr->users()) {
      const auto inst_user = llvm::dyn_cast<llvm::IntToPtrInst>(user);
      if (!inst_user || inst_user == addr_inst ||
          inst_user->getParent() != bb) {
        continue;
      }

      for (auto next_inst = inst_user->getNextNode(); next_inst;
           next_inst = next_inst->getNextNode()) {
        DCHECK_EQ(next_inst->getParent(), bb);

        // We've found `addr_inst`, i.e. the address we're pointer that we're
        // try to compute follows a previous equivalent computation in the same
        // block, so we'll go take that one.
        if (next_inst == addr_inst) {
          return ir.CreateBitCast(inst_user, dest_type);
        }
      }

      // We found another computation of this pointer, but it follows
      // `addr_inst` in the block, so we'll move it to where we need it.
      inst_user->removeFromParent();
      inst_user->insertBefore(addr_inst);
      return ir.CreateBitCast(inst_user, dest_type);
    }

    return GetPointerFromInt(ir, addr, elem_type, addr_space);

  } else {
    CHECK(addr_type->isPointerTy());
    return ir.CreateBitCast(addr, dest_type);
  }
}

// Lower a memory read intrinsic into a `load` instruction.
static void ReplaceMemReadOp(const NativeModule *cfg_module, const char *name,
                             llvm::Type *val_type) {
  auto func = gModule->getFunction(name);
  if (!func) {
    return;
  }

  CHECK(func->isDeclaration())
      << "Cannot lower already implemented memory intrinsic " << name;

  auto callers = remill::CallersOf(func);
  for (auto call_inst : callers) {
    auto addr = call_inst->getArgOperand(1);
    llvm::IRBuilder<> ir(call_inst);
    llvm::Value *ptr = GetPointer(cfg_module, ir, addr, val_type, 0);
    llvm::Value *val = ir.CreateLoad(ptr);
    if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(val);
        FLAGS_volatile_memops && load_inst) {
      load_inst->setVolatile(true);
    }
    if (val_type->isX86_FP80Ty() || val_type->isFP128Ty()) {
      val = ir.CreateFPTrunc(val, func->getReturnType());
    }
    call_inst->replaceAllUsesWith(val);
  }
  for (auto call_inst : callers) {
    call_inst->eraseFromParent();
  }
  RemoveFunction(func);
}

// Lower a memory write intrinsic into a `store` instruction.
static void ReplaceMemWriteOp(const NativeModule *cfg_module, const char *name,
                              llvm::Type *val_type) {
  auto func = gModule->getFunction(name);
  if (!func) {
    return;
  }

  CHECK(func->isDeclaration())
      << "Cannot lower already implemented memory intrinsic " << name;

  auto callers = remill::CallersOf(func);

  for (auto call_inst : callers) {
    auto mem_ptr = call_inst->getArgOperand(0);
    auto addr = call_inst->getArgOperand(1);
    auto val = call_inst->getArgOperand(2);

    llvm::IRBuilder<> ir(call_inst);
    llvm::Value *ptr = GetPointer(cfg_module, ir, addr, val_type, 0);
    if (val_type->isX86_FP80Ty() || val_type->isFP128Ty()) {
      val = ir.CreateFPExt(val, val_type);
    }

    auto store_inst = ir.CreateStore(val, ptr);
    if (FLAGS_volatile_memops) {
      store_inst->setVolatile(true);
    }
    call_inst->replaceAllUsesWith(mem_ptr);
  }
  for (auto call_inst : callers) {
    call_inst->eraseFromParent();
  }
  RemoveFunction(func);
}

static void LowerMemOps(const NativeModule *cfg_module) {
  ReplaceMemReadOp(cfg_module, "__remill_read_memory_8",
                   llvm::Type::getInt8Ty(*gContext));
  ReplaceMemReadOp(cfg_module, "__remill_read_memory_16",
                   llvm::Type::getInt16Ty(*gContext));
  ReplaceMemReadOp(cfg_module, "__remill_read_memory_32",
                   llvm::Type::getInt32Ty(*gContext));
  ReplaceMemReadOp(cfg_module, "__remill_read_memory_64",
                   llvm::Type::getInt64Ty(*gContext));
  ReplaceMemReadOp(cfg_module, "__remill_read_memory_f32",
                   llvm::Type::getFloatTy(*gContext));
  ReplaceMemReadOp(cfg_module, "__remill_read_memory_f64",
                   llvm::Type::getDoubleTy(*gContext));

  ReplaceMemWriteOp(cfg_module, "__remill_write_memory_8",
                    llvm::Type::getInt8Ty(*gContext));
  ReplaceMemWriteOp(cfg_module, "__remill_write_memory_16",
                    llvm::Type::getInt16Ty(*gContext));
  ReplaceMemWriteOp(cfg_module, "__remill_write_memory_32",
                    llvm::Type::getInt32Ty(*gContext));
  ReplaceMemWriteOp(cfg_module, "__remill_write_memory_64",
                    llvm::Type::getInt64Ty(*gContext));
  ReplaceMemWriteOp(cfg_module, "__remill_write_memory_f32",
                    llvm::Type::getFloatTy(*gContext));
  ReplaceMemWriteOp(cfg_module, "__remill_write_memory_f64",
                    llvm::Type::getDoubleTy(*gContext));

  ReplaceMemReadOp(cfg_module, "__remill_read_memory_f80",
                   llvm::Type::getX86_FP80Ty(*gContext));
  ReplaceMemReadOp(cfg_module, "__remill_write_memory_f128",
                   llvm::Type::getFP128Ty(*gContext));

  ReplaceMemWriteOp(cfg_module, "__remill_write_memory_f80",
                    llvm::Type::getX86_FP80Ty(*gContext));
  ReplaceMemWriteOp(cfg_module, "__remill_write_memory_f128",
                    llvm::Type::getFP128Ty(*gContext));
}

static bool RemoveDeadRestores(llvm::Function *restorer) {
  std::vector<std::pair<llvm::CallInst *, llvm::Value *>> to_replace;
  std::vector<llvm::Instruction *> to_remove;
  std::vector<llvm::Instruction *> try_to_remove;
  std::vector<std::pair<llvm::Use *, llvm::Value *>> to_fixup;

  std::unordered_set<llvm::Function *> functions_with_noreturn;
  if (FLAGS_restore_all_on_unreachable) {
    for (auto &func : *gModule) {
      if (func.doesNotReturn()) {
        for (auto user : func.users()) {
          if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user);
              call_inst && call_inst->getCalledFunction() == &func) {
            functions_with_noreturn.insert(call_inst->getParent()->getParent());

          } else if (auto invoke_inst = llvm::dyn_cast<llvm::InvokeInst>(user);
                     invoke_inst && invoke_inst->getCalledFunction() == &func) {
            functions_with_noreturn.insert(
                invoke_inst->getParent()->getParent());
          }
        }
      }
      for (auto &block : func) {
        if (llvm::isa<llvm::UnreachableInst>(block.getTerminator())) {
          functions_with_noreturn.insert(&func);
        }
      }
    }
  }

  auto needs_restores = false;
  do {
    for (auto [use, new_val] : to_fixup) {
      use->set(new_val);
    }

    to_replace.clear();
    to_remove.clear();
    try_to_remove.clear();
    to_fixup.clear();

    for (auto user : restorer->users()) {
      const auto call = llvm::dyn_cast<llvm::CallInst>(user);
      if (!call) {
        continue;
      }

      auto args = call->arg_begin();
      auto first_arg = args->get();
      auto second_arg = (++args)->get();
      auto func = call->getParent()->getParent();

      // If the two arguments match, then it means that the register being
      // restored didn't change over the course of this function.
      //
      // NOTE(pag): If a function has an unreachable instruction, then it might
      //            miss out on some optimizations, and so we want to always
      //            force some restores.
      if (first_arg == second_arg && (!FLAGS_restore_all_on_unreachable ||
                                      !functions_with_noreturn.count(func))) {
        auto all_users_are_stores = true;

        // Go find the store of the return value to the state structure, and
        // schedule it for removal.
        for (auto &call_use : call->uses()) {
          const auto call_user = call_use.getUser();
          if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(call_user);
              store_inst) {
            to_remove.emplace_back(store_inst);

          // Check to see if one `__remill_restore` function's output leads to
          // another one's, and then queue up a replacement that will send us
          // back around the main loop.
          } else if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(call_user);
                     call_inst) {
            if (call_inst == call) {
              continue;  // Weird?

            } else if (call_inst->getCalledFunction() == restorer) {
              to_fixup.emplace_back(&call_use, call_inst->arg_begin()->get());
            } else {
              all_users_are_stores = false;
            }
          } else {
            all_users_are_stores = false;
          }
        }

        // Go look for any stores of the first argument into the state structure,
        // and remove them. If we find these, then they are likely leftovers from
        // after function calls to other lifted functions.
        if (auto reg_load = llvm::dyn_cast<llvm::LoadInst>(first_arg);
            reg_load) {
          for (auto reg_user : first_arg->users()) {
            if (auto reg_restore = llvm::dyn_cast<llvm::StoreInst>(reg_user);
                reg_restore) {

              // Found a save of the register back into itself.
              if (reg_load->getPointerOperand() ==
                  reg_restore->getPointerOperand()) {
                to_remove.push_back(reg_restore);
              }
            }
          }
        }

        if (!all_users_are_stores) {
          to_replace.emplace_back(call, first_arg);
        }

      } else {
        needs_restores = true;

        for (auto call_user : call->users()) {
          if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(call_user)) {
            store_inst->setVolatile(false);
          }
        }
        to_replace.emplace_back(call, first_arg);

        // The `load` of the most recent value in that register.
        if (auto inst = llvm::dyn_cast<llvm::Instruction>(second_arg)) {
          try_to_remove.push_back(inst);
        }
      }

      to_remove.push_back(call);
    }
  } while (!to_fixup.empty());

  std::unordered_set<llvm::Value *> removed;

  for (auto [call_inst, orig_val] : to_replace) {
    call_inst->replaceAllUsesWith(orig_val);
  }

  removed.reserve(to_remove.size() + try_to_remove.size());

  for (auto inst : to_remove) {
    if (!removed.count(inst)) {
      inst->eraseFromParent();
      removed.insert(inst);
    }
  }

  for (auto inst : try_to_remove) {
    if (!removed.count(inst) && !inst->hasNUsesOrMore(1)) {
      inst->eraseFromParent();
      removed.insert(inst);
    }
  }

  return needs_restores;
}

static bool RemoveDeadRestores(void) {
  auto needs_restores = false;
  std::vector<llvm::Function *> to_remove;
  for (auto &func : *gModule) {
    if (func.getName().startswith("__remill_restore.")) {
      needs_restores = RemoveDeadRestores(&func) || needs_restores;
      to_remove.push_back(&func);
    }
  }
  for (auto func : to_remove) {
    func->eraseFromParent();
  }
  return needs_restores;
}

static void RemoveKilledStores(void) {
  if (auto killer = gModule->getGlobalVariable("__remill_kill"); killer) {
    std::vector<std::pair<llvm::CallInst *, llvm::Value *>> to_replace;
    std::vector<llvm::Instruction *> to_remove;
    std::vector<llvm::Value *> work_list;
    std::vector<llvm::Value *> next_work_list;
    next_work_list.push_back(killer);

    while (!next_work_list.empty()) {
      work_list.swap(next_work_list);
      next_work_list.clear();
      for (auto val : work_list) {
        for (auto user : val->users()) {
          if (auto si = llvm::dyn_cast<llvm::StoreInst>(user); si) {
            to_remove.emplace_back(si);
          } else if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(user); ce) {
            next_work_list.push_back(ce);
          }
        }
      }
    }

    std::sort(to_remove.begin(), to_remove.end());
    auto it = std::unique(to_remove.begin(), to_remove.end());
    to_remove.erase(it, to_remove.end());
    for (auto inst : to_remove) {
      inst->eraseFromParent();
    }

    killer->replaceAllUsesWith(llvm::UndefValue::get(killer->getType()));
    killer->eraseFromParent();
  }
}

// When implementing the save/restore optimization, we can sometimes have an
// annoying interaction with no-return functions. Here's an example:
//
//    lifted_foo {
//      orig_rbp = state->rbp
//      ...
//      state->rbp = state->rsp  // From instruction semantics
//      ...
//
//      saved_rbp = state->rbp
//      state->rbp = __remill_saving_kill_XXX(saved_rbp)  // To kill `state->rbp`
//      lifted_bar()  // May be noreturn, and if so, the rest gets eliminated
//      state->rbp = saved_rbp  // To propagate `saved_rbp` around
//
//      ...
//
//      state->rbp = orig_rbp
//      ret
//    }
//
// So the issue that can happen is that if `lifted_bar` is `noreturn`, then a
// bunch of stores into the state struct can get eliminated. If those stores
// get eliminated, then it's possible that `state->rbp` is treated as being
// live when `state->rbp = state->rsp` happens, and so that store will happen
// and a caller might see the callee's `rbp` instead of `orig_rbp`. By
// introducing the call and store `state->rbp = __remill_saving_kill_XXX...`,
// we make sure that there is always a store to a saved/restored reg, even
// before noreturn functions, and so the store `state->rbp = state->rsp` is
// marked as dead, and so the calle sees the right `rbp` upon return.
static void RemoveSavingKilledStores(void) {

  std::vector<std::pair<llvm::CallInst *, llvm::Value *>> to_replace;
  std::vector<llvm::StoreInst *> to_remove;

  for (auto &func : *gModule) {
    if (func.getName().startswith("__remill_saving_kill_")) {
      for (auto user : func.users()) {
        if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user);
            call_inst && call_inst->getCalledFunction() == &func) {
          to_replace.emplace_back(call_inst, call_inst->getArgOperand(0));
        }
      }
    }
  }

  for (auto [kill_val, reg_val] : to_replace) {
    if (auto store_inst =
            llvm::dyn_cast<llvm::StoreInst>(kill_val->getNextNode());
        store_inst && store_inst->getValueOperand() == kill_val) {
      to_remove.push_back(store_inst);
    }

    kill_val->replaceAllUsesWith(reg_val);
    kill_val->eraseFromParent();
  }

  for (auto store_inst : to_remove) {
    store_inst->eraseFromParent();
  }
}

// Adapt a constant (possibly expression) of integral type in `src` to another
// integer type (likely `gWordType`) that is `dest_type`.
static llvm::Constant *AdaptToType(llvm::Constant *src, llvm::Type *dest_type) {
  const auto src_type = src->getType();
  if (src_type == dest_type) {
    return src;
  }
  CHECK(src_type->isIntegerTy());

  if (dest_type->isIntegerTy()) {
    auto src_size = src_type->getPrimitiveSizeInBits();
    auto dest_size = dest_type->getPrimitiveSizeInBits();
    if (src_size < dest_size) {
      return llvm::ConstantExpr::getZExt(src, dest_type);
    } else {
      return llvm::ConstantExpr::getTrunc(src, dest_type);
    }
  } else if (dest_type->isPointerTy()) {
    if (auto pti = llvm::dyn_cast<llvm::PtrToIntOperator>(src); pti) {
      src = llvm::cast<llvm::Constant>(pti->getOperand(0));
      if (src->getType() == dest_type) {
        return src;
      } else {
        return llvm::ConstantExpr::getBitCast(src, dest_type);
      }

    } else {
      return llvm::ConstantExpr::getIntToPtr(src, dest_type);
    }
  } else {
    LOG(FATAL) << "Unsupported destination type: "
               << remill::LLVMThingToString(dest_type);
    return nullptr;
  }
}
// The add-on pass to merge the `GEP` instructions if they are operating
// on the same instruction operand
static void MergeGEPInstructions(llvm::Function &func) {
  std::map<std::pair<llvm::Value *, llvm::Value *>,
           std::vector<llvm::Instruction *>>
      gep_map;

  for (auto &block : func) {
    for (auto &inst : block) {
      if ((inst.getNumOperands() != 2))
        continue;

      if ((inst.getOpcode() == llvm::Instruction::GetElementPtr) &&
          (llvm::isa<llvm::Instruction>(inst.getOperand(0))) &&
          (llvm::isa<llvm::Constant>(inst.getOperand(1)))) {
        gep_map[std::pair<llvm::Value *, llvm::Value *>(inst.getOperand(0),
                                                        inst.getOperand(1))]
            .push_back(&inst);
      }
    }
  }

  for (auto it = gep_map.begin(); it != gep_map.end(); ++it) {
    auto &inst_vec = it->second;
    if (inst_vec.size() == 1) {
      continue;
    }

    auto opnd0 = llvm::dyn_cast<llvm::Instruction>(inst_vec[0]->getOperand(0));
    if ((opnd0->getOpcode() == llvm::Instruction::PHI))
      continue;

    inst_vec[0]->moveAfter(opnd0);

    for (auto i = 1u; i < inst_vec.size(); ++i) {
      auto gep_to_merge = inst_vec[i];
      gep_to_merge->replaceAllUsesWith(inst_vec[0]);

      if (!gep_to_merge->hasNUsesOrMore(1)) {
        gep_to_merge->eraseFromParent();
      }
    }
  }
}

// Lower cross-references, and try to fixup pointers.
static void LowerXrefs(const NativeModule *cfg_module) {
  std::vector<llvm::Constant *> work_list;
  std::vector<llvm::Constant *> next_work_list;
  std::vector<std::pair<llvm::Use *, llvm::Value *>> fixups;
  std::unordered_map<llvm::Constant *, llvm::Constant *> done_fixups;

  anvill::XrefExprFolder folder(*cfg_module, *gModule);

  auto get_fixup = [=, &folder, &done_fixups](
                       llvm::User *user,
                       llvm::Constant *ce) -> llvm::Constant * {
    bool is_bitwise = false;
    if (auto op = llvm::dyn_cast<llvm::BinaryOperator>(user); op) {
      switch (op->getOpcode()) {
        case llvm::Instruction::AShr:
        case llvm::Instruction::LShr:
        case llvm::Instruction::Shl:
        case llvm::Instruction::And:
        case llvm::Instruction::Xor:
        case llvm::Instruction::Or:

          //is_bitwise = true;
          break;
        default: break;
      }
    }

    const auto ce_type = ce->getType();
    auto &fixup = done_fixups[ce];
    if (!is_bitwise && fixup) {
      return fixup;
    }

    folder.Reset();
    const auto ea = folder.VisitConst(ce);

    if (remill::IsError(folder.error)) {
      LOG(ERROR) << remill::GetErrorString(folder.error);
    }

    // Common to have a shift left by one, two, or three for common
    // optimizations and address calculations (e.g. multiply by pointer or
    // offset size).
    //if (is_bitwise && folder.left_shift_amount <= 3) {
    //  is_bitwise = false;
    //}

    // It's a small number, just treat it like a constant.
    if (llvm::isa<llvm::IntegerType>(ce_type) &&
        (ea < 128 || (ea < 4096 && !FLAGS_check_for_lowmem_xrefs))) {
      fixup = llvm::ConstantInt::get(ce_type, ea);

    // Try to map it to a segment, external variable, or function.
    } else if (auto addr = GetAddress(cfg_module, ea)) {
      fixup = AdaptToType(addr, ce_type);

    // It doesn't reference anything known; treat it as a constant.
    } else {
      if (auto inst = llvm::dyn_cast<llvm::Instruction>(user); inst) {
        LOG(WARNING) << "Treating " << std::hex << ea << std::dec
                     << " as a constant"
                     << " in " << inst->getParent()->getName().str();

      } else {
        LOG(WARNING) << "Treating " << std::hex << ea << std::dec
                     << " as a constant";
      }

      fixup = llvm::ConstantInt::get(ce_type, ea);
    }

    if (is_bitwise) {
      if (fixup) {
        if (llvm::isa<llvm::ConstantInt>(fixup)) {
          return fixup;
        } else {
          LOG(ERROR) << "Previously lifted cross-reference to " << std::hex
                     << ea << std::dec
                     << " is used in subsequent bitwise operations; "
                     << "assuming it is actually a constant in this instance";

          return llvm::ConstantInt::get(ce_type, ea);
        }
      } else {
        LOG(ERROR)
            << "Cross-reference to " << std::hex << ea << std::dec
            << " is used in bitwise operations; assuming it is a constant";
        fixup = llvm::ConstantInt::get(ce_type, ea);
      }

    } else if (folder.bits_xor && !llvm::isa<llvm::ConstantInt>(fixup)) {
      fixup = llvm::ConstantInt::get(ce_type, ea);

      if (auto inst = llvm::dyn_cast<llvm::Instruction>(user); inst) {
        LOG(ERROR) << "Cross-reference to " << std::hex << ea << std::dec
                   << " in " << inst->getParent()->getName().str()
                   << " is computed via a XOR; assuming it is a constant: "
                   << remill::LLVMThingToString(ce);

      } else {
        LOG(ERROR) << "Cross-reference to " << std::hex << ea << std::dec
                   << " is computed via a XOR; assuming it is a constant: "
                   << remill::LLVMThingToString(ce);
      }
    }

    return fixup;
  };

  if (auto pc = gModule->getGlobalVariable("__anvill_pc"); pc) {
    next_work_list.push_back(pc);
  }

  // Sometimes, after optimizations, we'll end up seeing expressions operating
  // on our callback function pointers.
  for (auto [func_ea, cfg_func] : cfg_module->ea_to_func) {
    (void) func_ea;

    if (cfg_func->function) {
      if (auto func = gModule->getFunction(cfg_func->lifted_name); func) {
        cfg_func->function = func;
        for (auto &use : func->uses()) {
          const auto user = use.getUser();
          if (auto user_ce = llvm::dyn_cast<llvm::ConstantExpr>(user)) {
            next_work_list.push_back(user_ce);
          }
        }
      } else {
        cfg_func->function = nullptr;
      }
    }
  }

  while (!next_work_list.empty()) {
    next_work_list.swap(work_list);
    next_work_list.clear();

    for (auto ce : work_list) {
      for (auto &use : ce->uses()) {
        const auto user = use.getUser();
        if (auto inst = llvm::dyn_cast<llvm::Instruction>(user); inst) {
          fixups.emplace_back(&use, get_fixup(inst, ce));

        } else if (auto user_ce = llvm::dyn_cast<llvm::ConstantExpr>(user)) {
          next_work_list.push_back(user_ce);

        } else if (llvm::isa<llvm::GlobalVariable>(user) ||
                   llvm::isa<llvm::ConstantData>(user) ||
                   llvm::isa<llvm::ConstantAggregate>(user)) {
          continue;

        } else {
          LOG(ERROR) << "Unexpected user of cross-reference: "
                     << remill::LLVMThingToString(user);
        }
      }
    }
  }

  for (auto [use, replacement] : fixups) {
    use->set(replacement);
  }

  auto find_missed_fixup = [&](const char *func_name, llvm::Type *val_type) {
    const auto func = gModule->getFunction(func_name);
    if (!func) {
      return;
    }

    for (auto user : func->users()) {
      const auto ci = llvm::dyn_cast<llvm::CallInst>(user);
      if (!ci) {
        continue;
      }

      auto &addr_use = ci->getArgOperandUse(1);
      auto addr_val = addr_use.get();

      // If it's a constant integer, it means it was "missed" by the frontend
      // and thus by constant folding on `__mcsema_zero`.
      if (auto addr_int = llvm::dyn_cast<llvm::ConstantInt>(addr_val)) {
        const auto new_addr_val = get_fixup(user, addr_int);
        if (llvm::isa<llvm::ConstantInt>(new_addr_val)) {
          LOG(ERROR) << "Missed cross-reference to absolute address "
                     << std::hex << addr_int->getZExtValue() << std::dec
                     << " in block " << ci->getParent()->getName().str()
                     << " in function "
                     << ci->getParent()->getParent()->getName().str();

        } else {
          LOG(WARNING) << "Fixing absolute address " << std::hex
                       << addr_int->getZExtValue() << std::dec
                       << " to be reference "
                       << remill::LLVMThingToString(new_addr_val);
        }

        fixups.emplace_back(&addr_use, new_addr_val);

      // At this point, it should be an `ptrtoint` on a global, or an
      // instruction that computes an integer.
      } else {
        llvm::IRBuilder<> ir(ci);
        llvm::Value *ptr =
            GetPointer(cfg_module, ir, addr_use.get(), val_type, 0);
        fixups.emplace_back(&addr_use, ir.CreatePtrToInt(ptr, gWordType));
      }
    }
  };

  // Clear out all prior fixups.
  fixups.clear();
  folder.Reset();

  const auto int8_ty = llvm::Type::getInt8Ty(*gContext);
  const auto int16_ty = llvm::Type::getInt16Ty(*gContext);
  const auto int32_ty = llvm::Type::getInt32Ty(*gContext);
  const auto int64_ty = llvm::Type::getInt64Ty(*gContext);
  const auto float_ty = llvm::Type::getFloatTy(*gContext);
  const auto double_ty = llvm::Type::getDoubleTy(*gContext);
  const auto fp80_ty = llvm::Type::getX86_FP80Ty(*gContext);
  const auto fp128_ty = llvm::Type::getFP128Ty(*gContext);

  find_missed_fixup("__remill_read_memory_8", int8_ty);
  find_missed_fixup("__remill_read_memory_16", int16_ty);
  find_missed_fixup("__remill_read_memory_32", int32_ty);
  find_missed_fixup("__remill_read_memory_64", int64_ty);
  find_missed_fixup("__remill_read_memory_f32", float_ty);
  find_missed_fixup("__remill_read_memory_f64", double_ty);
  find_missed_fixup("__remill_read_memory_f80", fp80_ty);
  find_missed_fixup("__remill_read_memory_f128", fp128_ty);

  find_missed_fixup("__remill_compare_exchange_memory_8", int8_ty);
  find_missed_fixup("__remill_fetch_and_add_8", int8_ty);
  find_missed_fixup("__remill_fetch_and_sub_8", int8_ty);
  find_missed_fixup("__remill_fetch_and_or_8", int8_ty);
  find_missed_fixup("__remill_fetch_and_and_8", int8_ty);
  find_missed_fixup("__remill_fetch_and_xor_8", int8_ty);

  find_missed_fixup("__remill_compare_exchange_memory_16", int16_ty);
  find_missed_fixup("__remill_fetch_and_add_16", int16_ty);
  find_missed_fixup("__remill_fetch_and_sub_16", int16_ty);
  find_missed_fixup("__remill_fetch_and_or_16", int16_ty);
  find_missed_fixup("__remill_fetch_and_and_16", int16_ty);
  find_missed_fixup("__remill_fetch_and_xor_16", int16_ty);

  find_missed_fixup("__remill_compare_exchange_memory_32", int32_ty);
  find_missed_fixup("__remill_fetch_and_add_32", int32_ty);
  find_missed_fixup("__remill_fetch_and_sub_32", int32_ty);
  find_missed_fixup("__remill_fetch_and_or_32", int32_ty);
  find_missed_fixup("__remill_fetch_and_and_32", int32_ty);
  find_missed_fixup("__remill_fetch_and_xor_32", int32_ty);

  find_missed_fixup("__remill_compare_exchange_memory_64", int64_ty);
  find_missed_fixup("__remill_fetch_and_add_64", int64_ty);
  find_missed_fixup("__remill_fetch_and_sub_64", int64_ty);
  find_missed_fixup("__remill_fetch_and_or_64", int64_ty);
  find_missed_fixup("__remill_fetch_and_and_64", int64_ty);
  find_missed_fixup("__remill_fetch_and_xor_64", int64_ty);

  find_missed_fixup("__remill_write_memory_8", int8_ty);
  find_missed_fixup("__remill_write_memory_16", int16_ty);
  find_missed_fixup("__remill_write_memory_32", int32_ty);
  find_missed_fixup("__remill_write_memory_64", int64_ty);
  find_missed_fixup("__remill_write_memory_f32", float_ty);
  find_missed_fixup("__remill_write_memory_f64", double_ty);
  find_missed_fixup("__remill_write_memory_f80", fp80_ty);
  find_missed_fixup("__remill_write_memory_f128", fp128_ty);

  for (auto [use, replacement] : fixups) {
    use->set(replacement);
  }

  gZero = nullptr;
  if (auto zero = gModule->getNamedGlobal("__anvill_pc")) {
    zero->eraseFromParent();
  }
}

// Looks for calls to a function like `__remill_function_return`, and
// replace its state pointer with a null pointer so that the state
// pointer never escapes.
static void MuteStateEscape(const char *func_name) {
  auto func = gModule->getFunction(func_name);
  if (!func) {
    return;
  }

  const auto state_ptr = GetStatePointer();
  for (auto user : func->users()) {
    if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user)) {
      call_inst->setArgOperand(remill::kStatePointerArgNum, state_ptr);
    }
  }
}

static void SanitizeNameForLinking(std::string &name) {
  for (auto &c : name) {
    if (!std::isalnum(c)) {
      c = '_';
    }
  }
}

// Try to get `ptr` as an alias to a register in the thread-local state
// structure.
static llvm::Value *TryGetRegAlias(llvm::Value *ptr, unsigned offset) {
  if (FLAGS_disable_aliases) {
    return ptr;
  }

  auto reg = gArch->RegisterAtStateOffset(offset);
  if (!reg) {
    return ptr;
  }

  reg = reg->EnclosingRegister();

  auto ptr_const = llvm::dyn_cast<llvm::Constant>(ptr);
  if (!ptr_const) {
    return ptr;
  }

  const auto ptr_type = ptr_const->getType();
  const auto elem_type = ptr_type->getPointerElementType();

  std::stringstream ss;
  ss << reg->name << '_' << offset << '_'
     << std::hex << reinterpret_cast<uintptr_t>(elem_type);
  auto alias_name = ss.str();
  SanitizeNameForLinking(alias_name);

  auto alias = gModule->getNamedAlias(alias_name);
  if (alias) {
    return alias;
  }

  alias = llvm::GlobalAlias::create(
      elem_type, ptr_type->getPointerAddressSpace(),
      llvm::GlobalValue::PrivateLinkage, alias_name, ptr_const, gModule.get());
  alias->setThreadLocalMode(llvm::GlobalValue::InitialExecTLSModel);
  return alias;
}

// Go replace all uses of the state pointer argument with the global state
// pointer, and try to look for the following patterns and also fold them
// into constant expressions:
//
//    %blah = ptrtoint %val       load %val, %reg_ptr
//    store %blah, %reg_ptr       %blah = intoptr %val
//
//                          into
//
//    store %val, (bitcast CE)    %blah = load (bitcast CE)
//
// So as to reduce the total number of GEPs and inttoptr instructions.
static void GlobalizeStateStructures(void) {
  const auto state_ptr = ::mcsema::GetStatePointer();
  const auto state_ptr_type = state_ptr->getType();

  //const auto undef_state = llvm::UndefValue::get(state_ptr_type);

  std::vector<std::pair<llvm::Value *, unsigned>> work_list;
  std::vector<std::pair<llvm::Value *, unsigned>> next_work_list;
  std::vector<std::pair<llvm::Use *, unsigned>> to_replace;
  std::vector<llvm::Instruction *> to_remove;

  const auto &dl = gModule->getDataLayout();

  for (auto &func : *gModule) {
    if (func.isDeclaration()) {
      continue;
    }

    if (func.getFunctionType()->getNumParams() <= remill::kStatePointerArgNum) {
      continue;
    }

    auto func_state_ptr =
        remill::NthArgument(&func, remill::kStatePointerArgNum);
    if (func_state_ptr->getType() != state_ptr_type) {
      continue;
    }
#if 0

    // Replace all state pointer args with `undef`.
    for (auto user : func.users()) {
      if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user);
          call_inst && call_inst->getCalledFunction() == &func) {
        call_inst->setArgOperand(remill::kStatePointerArgNum, undef_state);
      }
    }
#endif
    to_replace.clear();
    to_remove.clear();
    next_work_list.clear();
    next_work_list.emplace_back(func_state_ptr, 0);
    while (!next_work_list.empty()) {
      work_list.clear();
      next_work_list.swap(work_list);
      for (auto [ptr_, offset] : work_list) {
        llvm::Value *ptr = ptr_;
        for (auto &use : ptr->uses()) {
          auto user = use.getUser();
          if (auto bc = llvm::dyn_cast<llvm::BitCastInst>(user); bc) {
            next_work_list.emplace_back(bc, offset);
            to_remove.push_back(bc);

          } else if (auto gep = llvm::dyn_cast<llvm::GetElementPtrInst>(user);
                     gep) {
            llvm::APInt sub_offset(gArch->address_size, 0);
            if (gep->accumulateConstantOffset(dl, sub_offset)) {
              next_work_list.emplace_back(gep,
                                          offset + sub_offset.getZExtValue());

            } else {
              to_replace.emplace_back(&use, offset);
            }
            to_remove.push_back(gep);

          } else if (llvm::isa<llvm::CallInst>(user) ||
                     llvm::isa<llvm::InvokeInst>(user) ||
                     llvm::isa<llvm::StoreInst>(user)) {
            to_replace.emplace_back(&use, offset);

          } else if (auto inst = llvm::dyn_cast<llvm::Instruction>(user);
                     inst) {

            to_replace.emplace_back(&use, offset);
            to_remove.push_back(inst);

          } else {
            to_replace.emplace_back(&use, offset);
          }
        }
      }
    }

    llvm::IRBuilder<> ir(&(func.getEntryBlock()),
                         func.getEntryBlock().getFirstInsertionPt());

    for (auto [use, offset] : to_replace) {
      auto user = use->getUser();

      // Match on the store pattern that we want to simplify, if possible.
      if (auto store = llvm::dyn_cast<llvm::StoreInst>(user); store) {
        auto base = store->getValueOperand();

        if (auto pti = llvm::dyn_cast<llvm::PtrToIntOperator>(base); pti) {
          auto ptr = remill::BuildPointerToOffset(
              ir, state_ptr, offset,
              llvm::PointerType::get(pti->getPointerOperandType(), 0));
          ptr = TryGetRegAlias(ptr, offset);

          if (auto pti_inst = llvm::dyn_cast<llvm::Instruction>(pti);
              pti_inst) {
            to_remove.push_back(pti_inst);
          }

          (void) new llvm::StoreInst(pti->getPointerOperand(), ptr, store);
          to_remove.push_back(store);
          continue;
        }

      // Match on the load pattern that we want to simplify, if possible.
      } else if (auto load = llvm::dyn_cast<llvm::LoadInst>(user); load) {
        for (auto &load_use : load->uses()) {
          auto user = load_use.getUser();
          if (auto itp = llvm::dyn_cast<llvm::IntToPtrInst>(user)) {
            auto ptr = remill::BuildPointerToOffset(
                ir, state_ptr, offset,
                llvm::PointerType::get(itp->getType(), 0));
            ptr = TryGetRegAlias(ptr, offset);
            itp->replaceAllUsesWith(
#if LLVM_VERSION_NUMBER < LLVM_VERSION(11, 0)
                new llvm::LoadInst(ptr, load->getName(), load)
#else
                new llvm::LoadInst(ptr->getType(), ptr, load->getName(), load)
#endif
                );
            to_remove.push_back(itp);
          }
        }
      }

      auto ptr = remill::BuildPointerToOffset(ir, state_ptr, offset,
                                              use->get()->getType());

      ptr = TryGetRegAlias(ptr, offset);
      use->set(ptr);
    }

    std::sort(to_remove.begin(), to_remove.end());
    auto remove_it = std::unique(to_remove.begin(), to_remove.end());
    to_remove.erase(remove_it, to_remove.end());

    while (!to_remove.empty()) {
      auto inst = to_remove.back();
      to_remove.pop_back();
      if (!inst->hasNUsesOrMore(1)) {
        inst->eraseFromParent();
      }
    }
  }
}

static void MuteLinkerSymbol(const char *sym_name) {
  if (auto gv = gModule->getGlobalVariable(sym_name); gv) {
    gv->setLinkage(llvm::GlobalValue::PrivateLinkage);
  }
}

}  // namespace

void OptimizeModule(const NativeModule *cfg_module) {

  if (auto llvm_used = gModule->getGlobalVariable("llvm.used")) {
    llvm_used->eraseFromParent();
  }

  MuteStateEscape("__remill_function_return");
  MuteStateEscape("__remill_jump");
  MuteStateEscape("__remill_error");
  MuteStateEscape("__remill_missing_block");
  MuteStateEscape("__remill_async_hyper_call");

  auto isels = FindISELs();
  LOG(INFO) << "Optimizing module.";

  PrivatizeISELs(isels);

  auto bb_func = remill::BasicBlockFunction(gModule.get());
  auto slots = remill::StateSlots(gArch.get(), gModule.get());

  if (auto llvm_used = gModule->getGlobalVariable("llvm.used")) {
    llvm_used->eraseFromParent();
  }

  llvm::legacy::PassManager mod_pm;
  mod_pm.add(llvm::createFunctionInliningPass(250));
  mod_pm.run(*gModule);

  llvm::legacy::FunctionPassManager pm(gModule.get());

  //    pm.add(llvm::createGVNHoistPass());
  //    pm.add(llvm::createGVNSinkPass());
  //    pm.add(llvm::createMergedLoadStoreMotionPass());

  pm.add(llvm::createEarlyCSEPass(true));
  pm.add(llvm::createDeadCodeEliminationPass());
  pm.add(llvm::createConstantPropagationPass());
  pm.add(llvm::createSinkingPass());
  pm.add(llvm::createNewGVNPass());
  pm.add(llvm::createSCCPPass());
  pm.add(llvm::createDeadStoreEliminationPass());
  pm.add(llvm::createSROAPass());
  pm.add(llvm::createPromoteMemoryToRegisterPass());
  pm.add(llvm::createBitTrackingDCEPass());
  pm.add(llvm::createCFGSimplificationPass());
  pm.add(llvm::createSinkingPass());
  pm.add(llvm::createCFGSimplificationPass());

  pm.doInitialization();
  for (auto &func : *gModule) {
    pm.run(func);
  }
  pm.doFinalization();

  remill::RemoveDeadStores(gArch.get(), gModule.get(), bb_func, slots);

  // If some of the restores are *not* dead, then we will have eliminated
  // some loads and subsequent uses (in the `__remill_restore.*` argument lists)
  // that made those registers look live. The addition of restoring stores thus
  // means that there may be new DSE opportunities.
  if (RemoveDeadRestores()) {
    remill::RemoveDeadStores(gArch.get(), gModule.get(), bb_func, slots);
    pm.doInitialization();
    for (auto &func : *gModule) {
      pm.run(func);
    }
    pm.doFinalization();
  }

  RemoveKilledStores();

  // NOTE(pag): These are not done in Function.cpp atm.
  if (false) {
    RemoveSavingKilledStores();
  }

  //  anvill::RecoverMemoryAccesses(*cfg_module, *gModule);
  LowerXrefs(cfg_module);

  for (auto &[ea, cfg_func] : cfg_module->ea_to_func) {
    (void) ea;

    // Make sure things like `main` show up.
    if (cfg_func->is_exported) {
      (void) cfg_func->Pointer();
    }

    cfg_func->lifted_function = gModule->getFunction(cfg_func->lifted_name);

    //    if (!cfg_func->is_exported && cfg_func->function) {
    //      if (cfg_func->function->hasNUsesOrMore(1)) {
    //        continue;
    //      }
    //    }
  }

  pm.doInitialization();
  for (auto &func : *gModule) {
    pm.run(func);
  }
  pm.doFinalization();

  for (auto &func : *gModule) {
    MergeGEPInstructions(func);
  }

  pm.doInitialization();
  for (auto &func : *gModule) {
    pm.run(func);
  }
  pm.doFinalization();
}

// Remove some of the Remill intrinsics.
void CleanUpModule(const NativeModule *cfg_module) {
  RemoveUndefFuncCalls();

  if (auto llvm_used = gModule->getGlobalVariable("llvm.used")) {
    llvm_used->eraseFromParent();
  }

  if (!FLAGS_keep_memops) {
    LowerMemOps(cfg_module);
    ReplaceBarrier("__remill_barrier_load_load");
    ReplaceBarrier("__remill_barrier_load_store");
    ReplaceBarrier("__remill_barrier_store_load");
    ReplaceBarrier("__remill_barrier_store_store");
    ReplaceBarrier("__remill_barrier_atomic_begin");
    ReplaceBarrier("__remill_barrier_atomic_end");
    ReplaceBarrier("__remill_delay_slot_begin");
    ReplaceBarrier("__remill_delay_slot_end");
    ReplaceBarrier("__remill_atomic_begin");
    ReplaceBarrier("__remill_atomic_end");

    llvm::legacy::FunctionPassManager pm(gModule.get());
    pm.add(llvm::createEarlyCSEPass(true));
    pm.add(llvm::createDeadCodeEliminationPass());
    pm.add(llvm::createCFGSimplificationPass());
    pm.doInitialization();
    for (auto &func : *gModule) {
      pm.run(func);
    }
    pm.doFinalization();
  }

  LowerXrefs(cfg_module);

  for (auto &[ea, cfg_func] : cfg_module->ea_to_func) {
    (void) ea;

    cfg_func->lifted_function = gModule->getFunction(cfg_func->lifted_name);
    if (cfg_func->lifted_function) {
      cfg_func->lifted_function->setLinkage(llvm::GlobalValue::InternalLinkage);
    }
  }


  //  // Go try to inline
  //  for (const auto &func : cfg_module->functions) {
  //    if (func->lifted_function) {
  //      func->lifted_function = gModule->getFunction(func->lifted_name);
  //    }
  //
  //    if (func->lifted_function)
  //
  //    if (func->function) {
  //      func->function = gModule->getFunction(func->name);
  //    }
  //
  //    if (func->function &&
  //        func->lifted_function &&
  //        func->lifted_function->hasNUses(1)) {
  //
  //    }
  //  }

  std::vector<llvm::Function *> to_remove;
  do {
    to_remove.clear();
    for (auto &func : *gModule) {
      if (!func.isDeclaration()) {
        continue;
      }

      if (!func.hasNUsesOrMore(1)) {
        to_remove.push_back(&func);

      // E.g. `__libc_init`.
      } else if (func.hasInternalLinkage()) {
        func.setLinkage(llvm::GlobalValue::ExternalLinkage);
      }
    }

    for (auto func : to_remove) {
      func->eraseFromParent();
    }
  } while (!to_remove.empty());

  // This function makes removing intrinsics tricky, so if it's there, then
  // we'll try to get the optimizer to inline it on our behalf, which should
  // drop some references :-D
  if (auto remill_used = gModule->getFunction("__remill_mark_as_used")) {
    std::vector<llvm::CallInst *> uses;
    std::vector<llvm::Instruction *> to_remove;
    for (auto use : remill_used->users()) {
      if (auto call = llvm::dyn_cast<llvm::CallInst>(use)) {
        uses.push_back(call);
      }
    }

    for (auto call : uses) {
      for (const auto &arg : call->arg_operands()) {
        to_remove.push_back(llvm::dyn_cast<llvm::Instruction>(arg.get()));
      }
      call->eraseFromParent();
    }

    for (auto inst : to_remove) {
      if (inst && !inst->hasNUsesOrMore(1)) {
        inst->eraseFromParent();
      }
    }

    if (remill_used->hasNUsesOrMore(1)) {
      if (remill_used->isDeclaration()) {
        remill_used->setLinkage(llvm::GlobalValue::InternalLinkage);
        remill_used->removeFnAttr(llvm::Attribute::NoInline);
        remill_used->addFnAttr(llvm::Attribute::InlineHint);
        remill_used->addFnAttr(llvm::Attribute::AlwaysInline);
        auto block = llvm::BasicBlock::Create(*gContext, "", remill_used);
        (void) llvm::ReturnInst::Create(*gContext, block);
      }
    }

    RemoveFunction(remill_used);
  }

  if (auto intrinsics = gModule->getFunction("__remill_intrinsics")) {
    intrinsics->eraseFromParent();
  }

  RemoveFunction("__remill_intrinsics");
  RemoveFunction("__remill_basic_block");
  RemoveFunction("__remill_defer_inlining");
  RemoveFunction("__remill_undefined_8");
  RemoveFunction("__remill_undefined_16");
  RemoveFunction("__remill_undefined_32");
  RemoveFunction("__remill_undefined_64");
  RemoveFunction("__remill_undefined_f32");
  RemoveFunction("__remill_undefined_f64");
  RemoveFunction("__remill_undefined_f80");
  RemoveFunction("__remill_undefined_f128");

  if (!FLAGS_keep_memops) {
    RemoveFunction("__remill_read_memory_8");
    RemoveFunction("__remill_read_memory_16");
    RemoveFunction("__remill_read_memory_32");
    RemoveFunction("__remill_read_memory_64");
    RemoveFunction("__remill_read_memory_f32");
    RemoveFunction("__remill_read_memory_f64");
    RemoveFunction("__remill_read_memory_f80");
    RemoveFunction("__remill_read_memory_f128");

    RemoveFunction("__remill_write_memory_8");
    RemoveFunction("__remill_write_memory_16");
    RemoveFunction("__remill_write_memory_32");
    RemoveFunction("__remill_write_memory_64");
    RemoveFunction("__remill_write_memory_f32");
    RemoveFunction("__remill_write_memory_f64");
    RemoveFunction("__remill_write_memory_f80");
    RemoveFunction("__remill_write_memory_f128");

    RemoveFunction("__remill_compare_exchange_memory_8");
    RemoveFunction("__remill_fetch_and_add_8");
    RemoveFunction("__remill_fetch_and_sub_8");
    RemoveFunction("__remill_fetch_and_or_8");
    RemoveFunction("__remill_fetch_and_and_8");
    RemoveFunction("__remill_fetch_and_xor_8");

    RemoveFunction("__remill_compare_exchange_memory_16");
    RemoveFunction("__remill_fetch_and_add_16");
    RemoveFunction("__remill_fetch_and_sub_16");
    RemoveFunction("__remill_fetch_and_or_16");
    RemoveFunction("__remill_fetch_and_and_16");
    RemoveFunction("__remill_fetch_and_xor_16");

    RemoveFunction("__remill_compare_exchange_memory_32");
    RemoveFunction("__remill_fetch_and_add_32");
    RemoveFunction("__remill_fetch_and_sub_32");
    RemoveFunction("__remill_fetch_and_or_32");
    RemoveFunction("__remill_fetch_and_and_32");
    RemoveFunction("__remill_fetch_and_xor_32");

    RemoveFunction("__remill_compare_exchange_memory_64");
    RemoveFunction("__remill_fetch_and_add_64");
    RemoveFunction("__remill_fetch_and_sub_64");
    RemoveFunction("__remill_fetch_and_or_64");
    RemoveFunction("__remill_fetch_and_and_64");
    RemoveFunction("__remill_fetch_and_xor_64");
  }

  if (!FLAGS_local_state_pointer) {
    GlobalizeStateStructures();

    llvm::legacy::FunctionPassManager pm(gModule.get());
    pm.add(llvm::createEarlyCSEPass(true));
    pm.add(llvm::createDeadCodeEliminationPass());
    pm.add(llvm::createCFGSimplificationPass());
    pm.doInitialization();
    for (auto &func : *gModule) {
      pm.run(func);
    }
    pm.doFinalization();
  }

  MuteLinkerSymbol("__TMC_END__");
  MuteLinkerSymbol("__TMC_LIST__");
}

}  // namespace mcsema
