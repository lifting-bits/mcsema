/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <llvm/IR/Constants.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/Register.h"
#include "mcsema/BC/Util.h"

#include "mcsema/cfgToLLVM/TransExcn.h"

llvm::LLVMContext *gContext = nullptr;

llvm::Module *CreateModule(llvm::LLVMContext *context) {
  if (!gContext) {
    gContext = context;
  }
  auto M = new llvm::Module("", *context);
  M->setTargetTriple(ArchTriple());
  M->setDataLayout(ArchDataLayout());
  return M;
}

// Return a constnat integer of width `width` and value `val`.
llvm::ConstantInt *CreateConstantInt(int width, uint64_t val) {
  auto bTy = llvm::Type::getIntNTy(*gContext, width);
  return llvm::ConstantInt::get(bTy, val);
}

// Return the type of a lifted function.
llvm::FunctionType *LiftedFunctionType(void) {
  static llvm::FunctionType *func_type = nullptr;
  if (!func_type) {
    auto state_type = ArchRegStateStructType();
    auto state_ptr_type = llvm::PointerType::get(state_type, 0);
    std::vector<llvm::Type *> arg_types;
    arg_types.push_back(state_ptr_type);
    func_type = llvm::FunctionType::get(llvm::Type::getVoidTy(*gContext),
                                        arg_types, false);
  }
  return func_type;
}

llvm::Value *INTERNAL_M_READ(unsigned width, unsigned addrspace,
                             llvm::BasicBlock *b, llvm::Value *addr) {
  llvm::Value *readLoc = addr;
  llvm::LLVMContext &C = b->getContext();

  auto readLocTy = readLoc->getType();
  llvm::Type *PtrTy = llvm::Type::getIntNPtrTy(C, width, addrspace);

  if (readLocTy != PtrTy) {
    if (readLocTy->isPointerTy()) {
      llvm::DataLayout DL(b->getParent()->getParent());
      llvm::Type *IntPtrTy = DL.getIntPtrType(C, addrspace);
      readLoc = new llvm::PtrToIntInst(readLoc, IntPtrTy, "", b);
    }

    TASSERT(readLoc->getType()->isIntegerTy(), "Expected integer type.");
    readLoc = new llvm::IntToPtrInst(readLoc, PtrTy, "", b);
  }

  auto is_volatile = addrspace != 0;
  return new llvm::LoadInst(readLoc, "", is_volatile, b);
}

void INTERNAL_M_WRITE(int width, unsigned addrspace, llvm::BasicBlock *b,
                      llvm::Value *addr, llvm::Value *data) {
  llvm::Value *writeLoc = addr;
  llvm::LLVMContext &C = b->getContext();
  auto writeLocTy = writeLoc->getType();
  llvm::Type *PtrTy = llvm::Type::getIntNPtrTy(C, width, addrspace);

  if (writeLocTy != PtrTy) {
    if (writeLocTy->isPointerTy()) {
      llvm::DataLayout DL(b->getParent()->getParent());
      llvm::Type *IntPtrTy = DL.getIntPtrType(C, addrspace);
      writeLoc = new llvm::PtrToIntInst(writeLoc, IntPtrTy, "", b);
    }

    TASSERT(writeLoc->getType()->isIntegerTy(), "Expected integer type.");

    writeLoc = new llvm::IntToPtrInst(writeLoc, PtrTy, "", b);
  }

  auto is_volatile = addrspace != 0;
  (void) new llvm::StoreInst(data, writeLoc, is_volatile, b);
}

void M_WRITE_T(NativeInstPtr ip, llvm::BasicBlock *b, llvm::Value *addr,
               llvm::Value *data, llvm::Type *ptrtype) {
  //this is also straightforward
  llvm::Value *writeLoc = addr;
  unsigned addrspace = ip->get_addr_space();

  TASSERT(ptrtype->getPointerAddressSpace() == addrspace,
          "Mismatched pointer address spaces.");

  //however, if the incoming 'addr' location is not a pointer, we must
  //first turn it into an addr

  if (addr->getType()->isPointerTy() == false) {
    writeLoc = new llvm::IntToPtrInst(addr, ptrtype, "", b);
  } else if (addr->getType() != ptrtype) {
    writeLoc = llvm::CastInst::CreatePointerCast(addr, ptrtype, "", b);
  }

  (void) new llvm::StoreInst(data, writeLoc, b);
}

llvm::Value *ADDR_TO_POINTER(
    llvm::BasicBlock *b, llvm::Value *memAddr, int width) {
  auto ptrType = llvm::Type::getIntNPtrTy(b->getContext(), width);
  return ADDR_TO_POINTER_V(b, memAddr, ptrType);
}

llvm::Value *ADDR_TO_POINTER_V(llvm::BasicBlock *b, llvm::Value *memAddr,
                               llvm::Type *ptrType) {
  if (memAddr->getType()->isPointerTy() == false) {
    // its an integer, make it a pointer
    return new llvm::IntToPtrInst(memAddr, ptrType, "", b);
  } else if (memAddr->getType() != ptrType) {
    // its a pointer, but of the wrong type
    return llvm::CastInst::CreatePointerCast(memAddr, ptrType, "", b);
  } else {
    // already correct ptr type
    return memAddr;
  }
}

static llvm::Value *GetReadReg(llvm::Function *F, MCSemaRegs reg) {
  std::stringstream ss;
  ss << ArchRegisterName(reg) << "_read";
  auto reg_name = ss.str();

  for (llvm::Instruction &I : F->front()) {
    if (I.getName().str() == reg_name) {
      return &I;
    }
  }

  std::cerr
      << "Can't find variable " << reg_name << " for register number " << reg
      << " in function " << F->getName().str() << std::endl;
  return nullptr;
}

static llvm::Value *GetWriteReg(llvm::Function *F, MCSemaRegs reg) {
  std::stringstream ss;
  ss << ArchRegisterName(reg) << "_write";
  auto reg_name = ss.str();

  for (llvm::Instruction &I : F->front()) {
    if (I.getName().str() == reg_name) {
      return &I;
    }
  }

  std::cerr
      << "Can't find variable " << reg_name << " for register number " << reg
      << " in function " << F->getName().str() << std::endl;
  return nullptr;
}

void GENERIC_MC_WRITEREG(llvm::BasicBlock *B, MCSemaRegs mc_reg,
                         llvm::Value *val) {
  auto F = B->getParent();
  auto M = F->getParent();
  llvm::DataLayout DL(M);

  auto val_size = DL.getTypeAllocSizeInBits(val->getType());
  auto reg_ptr = GetWriteReg(F, mc_reg);

  auto reg_ptr_ty = llvm::dyn_cast<llvm::PointerType>(reg_ptr->getType());
  auto reg_ty = reg_ptr_ty->getElementType();
  auto reg_size = DL.getTypeAllocSizeInBits(reg_ty);

  if (val_size != reg_size) {
    if (val_size < reg_size) {
      val = new llvm::ZExtInst(val, reg_ty, "", B);
    } else {
      val = new llvm::TruncInst(val, reg_ty, "", B);
    }
  }

  (void) new llvm::StoreInst(val, reg_ptr, "", B);
}

llvm::Value *GENERIC_MC_READREG(llvm::BasicBlock *B, MCSemaRegs mc_reg,
                                int desired_size) {
  auto F = B->getParent();
  auto M = F->getParent();
  auto &C = M->getContext();

  if (llvm::X86::NoRegister == mc_reg) {
    std::cerr
        << "Reading 0 for no-register read-reg" << std::endl;
    return CreateConstantInt(desired_size, 0);
  }

  llvm::DataLayout DL(M);

  auto val_ptr = GetReadReg(F, mc_reg);
  llvm::Value *val = new llvm::LoadInst(val_ptr, "", B);
  auto val_ty = val->getType();
  auto val_size = DL.getTypeAllocSizeInBits(val_ty);

  if (desired_size != val_size) {
    if (val_ty->isIntegerTy()) {
      auto dst_ty = llvm::Type::getIntNTy(C, desired_size);
      if (desired_size < val_size) {
        val = new llvm::TruncInst(val, dst_ty, "", B);
      } else {
        val = new llvm::ZExtInst(val, dst_ty, "", B);
      }
    } else if (val_ty->isFloatTy()) {
      // TODO(pag): do something here?
    }
  }
  return val;
}

llvm::Value *GENERIC_READREG(llvm::BasicBlock *b, MCSemaRegs reg) {
  return GENERIC_MC_READREG(b, reg, ArchRegisterSize(reg));
}

void GENERIC_WRITEREG(llvm::BasicBlock *b, MCSemaRegs reg, llvm::Value *v) {
  return GENERIC_MC_WRITEREG(b, reg, v);
}

llvm::Value *F_READ(llvm::BasicBlock *b, MCSemaRegs flag, int size) {
  auto v = GENERIC_READREG(b, flag);
  auto &C = b->getContext();
  auto dest_ty = llvm::Type::getIntNTy(C, size);
  if (dest_ty != v->getType()) {
    v = new llvm::TruncInst(v, dest_ty, "", b);
  }
  return v;
}

llvm::Value *F_READ(llvm::BasicBlock *b, MCSemaRegs flag) {
  return F_READ(b, flag, 1);
}

void F_WRITE(llvm::BasicBlock *b, MCSemaRegs flag, llvm::Value *v) {
  auto &C = b->getContext();
  auto bool_ty = llvm::Type::getInt1Ty(C);
  auto int8_ty = llvm::Type::getInt8Ty(C);
  if (v->getType() != bool_ty) {
    v = new llvm::TruncInst(v, bool_ty, "", b);
  }
  v = new llvm::ZExtInst(v, int8_ty, "", b);
  return GENERIC_WRITEREG(b, flag, v);
}

void F_ZAP(llvm::BasicBlock *, MCSemaRegs) {

}

void F_SET(llvm::BasicBlock *b, MCSemaRegs flag) {
  F_WRITE(b, flag, CONST_V<8>(b, 1));
}

void F_CLEAR(llvm::BasicBlock *b, MCSemaRegs flag) {
  F_WRITE(b, flag, CONST_V<8>(b, 0));
}

static llvm::Constant *GetPointerSizedValue(llvm::Module *M, llvm::Constant *v,
                                            int valsize) {
  auto final_val = v;
  if (ArchPointerSize(M) == valsize) {
    return v;

  } else if (ArchPointerSize(M) == Pointer64 && valsize == 4) {
    auto int_val = llvm::ConstantExpr::getPtrToInt(
        v, llvm::Type::getInt64Ty(M->getContext()));
    final_val = llvm::ConstantExpr::getTrunc(
        int_val, llvm::Type::getInt32Ty(M->getContext()));
  }

  return final_val;
}


static llvm::GlobalVariable *GetSectionForDataAddr(
    const std::list<DataSection> &dataSecs, llvm::Module *M, VA data_addr,
    VA &section_base) {

  for (auto &dt : dataSecs) {
    VA start = dt.getBase();
    VA end = start + dt.getSize();

    if (data_addr >= start && data_addr < end) {
      std::stringstream ss;
      ss << "data_" << std::hex << start;
      section_base = start;
      return M->getNamedGlobal(ss.str());
    }
  }
  return nullptr;
}

static llvm::Constant *CreateConstantBlob(llvm::LLVMContext &ctx,
                                    const std::vector<uint8_t> &blob) {
  auto charTy = llvm::Type::getInt8Ty(ctx);
  auto arrT = llvm::ArrayType::get(charTy, blob.size());
  std::vector<llvm::Constant *> array_elements;
  for (auto cur : blob) {
    auto c = llvm::ConstantInt::get(charTy, cur);
    array_elements.push_back(c);
  }
  return llvm::ConstantArray::get(arrT, array_elements);
}

void dataSectionToTypesContents(const std::list<DataSection> &globaldata,
                                const DataSection &ds, llvm::Module *M,
                                std::vector<llvm::Constant *> &secContents,
                                std::vector<llvm::Type *> &data_section_types,
                                bool convert_to_callback) {
  // find what elements will be needed for this data section
  // There are three main types:
  // Functions: pointer to a known function in the cfg
  // Data Symbol: pointer to another data section item
  // Blob: opaque data treated as byte array
  //
  // The final data structure will look something like
  // struct data_section {
  //  function f1,
  //  function f2,
  //  uint8_t blob0[100];
  //  datasymbol d0;
  //  uint8_t blob1[200];
  //  ....
  //  };
  //
  const std::list<DataSectionEntry> &ds_entries = ds.getEntries();
  for (auto &data_sec_entry : ds_entries) {
    std::string sym_name;

    if (data_sec_entry.getSymbol(sym_name)) {

      std::cout
          << __FUNCTION__ << ": Found symbol: " << sym_name << " in "
          << std::hex << data_sec_entry.getBase() << std::endl;

      if (sym_name.find("ext_") == 0) {

        // TODO(pag): this is flaky!
        auto ext_sym_name = sym_name.c_str() + 4 /* strlen("ext_") */;

        llvm::Constant *final_val = nullptr;
        auto ext_v = M->getNamedValue(ext_sym_name);

        if (ext_v != nullptr && llvm::isa<llvm::Function>(ext_v)) {
          final_val = GetPointerSizedValue(M, ext_v, data_sec_entry.getSize());
          //cout << "External function" << sym_name << " has type: " << final_val->getType() << "\n";
        } else if (ext_v != nullptr) {
          final_val = GetPointerSizedValue(M, ext_v, data_sec_entry.getSize());
          //cout << "External data" << sym_name << " has type: " << final_val->getType() << "\n";
          // assume ext data
        } else {
          TASSERT(ext_v != nullptr,
                  "Could not find external: " + std::string(ext_sym_name));
          //cout << "External fail" << sym_name << " has type: " << final_val->getType() << "\n";
        }

        secContents.push_back(final_val);
        data_section_types.push_back(final_val->getType());

      } else if (sym_name.find("sub_") == 0) {

        // TODO(pag): This is so flaky.
        auto sub_addr_str = sym_name.c_str() + 4 /* strlen("sub_") */;
        VA sub_addr = 0;
        sscanf(sub_addr_str, "%lx", &sub_addr);

        // add function pointer to data section
        // to do this, create a callback driver for
        // it first (since it may be called externally)

        llvm::Function *func = nullptr;

        if (convert_to_callback) {
          func = ArchAddCallbackDriver(M, sub_addr);
          TASSERT(func != nullptr, "Could make callback for: " + sym_name);
        } else {
          func = M->getFunction(sym_name);
          TASSERT(func != nullptr, "Could not find function: " + sym_name);
        }

        auto final_val = GetPointerSizedValue(M, func, data_sec_entry.getSize());
        secContents.push_back(final_val);
        data_section_types.push_back(final_val->getType());

      } else if (sym_name.find("data_") == 0) {

        // TODO(pag): This is so flaky.
        auto data_addr_str = sym_name.c_str() + 5 /* strlen("data_") */;
        VA data_addr = 0;
        sscanf(data_addr_str, "%lx", &data_addr);

        // data symbol
        // get the base of the data section for this symobol
        // then compute the offset from base of data
        // and store as integer value of (base+offset)
        VA section_base;
        auto g_ref = GetSectionForDataAddr(globaldata, M, data_addr,
                                           section_base);
        TASSERT(g_ref != nullptr,
                "Could not get data addr for:" + std::string(data_addr_str));
        // instead of referencing an element directly
        // we just convert the pointer to an integer
        // and add its offset from the base of data
        // to the new data section pointer
        VA addr_diff = data_addr - section_base;
        llvm::Constant *final_val = nullptr;
        //cout << " Symbol name : " << string(func_addr_str) << " : "
        //     << to_string<VA>(func_addr, hex) << " : "
        //     << to_string<VA>(section_base, hex) << "\n";
        //cout.flush();
        if (ArchPointerSize(M) == Pointer32) {
          auto int_val = llvm::ConstantExpr::getPtrToInt(
              g_ref, llvm::Type::getInt32Ty(M->getContext()));
          final_val = llvm::ConstantExpr::getAdd(
              int_val, CONST_V_INT<32>(M->getContext(), addr_diff));
        } else {
          auto int_val = llvm::ConstantExpr::getPtrToInt(
              g_ref, llvm::Type::getInt64Ty(M->getContext()));
          final_val = llvm::ConstantExpr::getAdd(
              int_val, CONST_V_INT<64>(M->getContext(), addr_diff));
        }
        secContents.push_back(final_val);
        data_section_types.push_back(final_val->getType());

      } else {
        std::cerr
            << __FUNCTION__ << ": Unknown data section entry symbol type "
            << sym_name << std::endl;
      }
    } else {
      // add array
      // this holds opaque data in a byte array
      auto arr = CreateConstantBlob(M->getContext(), data_sec_entry.getBytes());
      secContents.push_back(arr);
      data_section_types.push_back(arr->getType());
    }  // if dsec_itr
  }  // for list
}
