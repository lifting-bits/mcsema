/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <iostream>
#include <unordered_map>
#include <vector>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Type.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/Register.h"
#include "mcsema/BC/Util.h"

namespace {

struct RegInfo {
  std::string name;
  MCSemaRegs reg;
  bool is_sub_reg;
  llvm::Type *read_type;
  llvm::Type *write_type;
  size_t state_offset;
  MCSemaRegs parent_reg;
  size_t parent_offset;
};

static const std::string gBadReg = "MISSING_REG";

static std::unordered_map<MCSemaRegs, RegInfo> gRegInfo;
static std::vector<RegInfo> gOrderedRegInfo;
static std::unordered_map<std::string, MCSemaRegs> gRegNum;

static std::vector<llvm::Type *> gRegFields;

static llvm::StructType *gRegStateStruct = nullptr;

static MCSemaRegs gLastAddedReg = llvm::X86::NoRegister;
static unsigned gNumRegs = 0;

static void AddPadding(llvm::Type *type, int num_elements) {
  gNumRegs++;
  gRegFields.push_back(llvm::ArrayType::get(type, num_elements));
  gLastAddedReg = llvm::X86::NoRegister;
}

static void AddReg(MCSemaRegs reg, const char *name, llvm::Type *type) {
  RegInfo info = {name, reg, false, type, type, gNumRegs++, reg, 0};
  gRegInfo[reg] = info;
  gRegNum[name] = reg;
  gRegFields.push_back(type);
  gOrderedRegInfo.push_back(info);
  gLastAddedReg = reg;
}

static void AddSubReg(MCSemaRegs reg, const char *name,
                      llvm::Type *read_type, llvm::Type *write_type,
                      size_t parent_offset) {
  RegInfo info = {name, reg, true, read_type, write_type,
                  gNumRegs, gLastAddedReg, parent_offset};
  gRegInfo[reg] = info;
  gOrderedRegInfo.push_back(info);

  if (!parent_offset) {
    gLastAddedReg = reg;
  }
}

}  // namespace

void X86InitRegisterState(llvm::LLVMContext *context) {
  if (!gContext) {
    gContext = context;
  }
  auto reg_type = llvm::Type::getIntNTy(*context, ArchAddressSize());
  auto int8_type = llvm::Type::getInt8Ty(*context);
  auto int16_type = llvm::Type::getInt16Ty(*context);
  auto int32_type = llvm::Type::getInt32Ty(*context);
  auto int64_type = llvm::Type::getInt64Ty(*context);
  auto int128_type = llvm::Type::getInt128Ty(*context);
  auto float80_type = llvm::Type::getX86_FP80Ty(*context);

  AddReg(llvm::X86::RIP, "RIP", reg_type);
  AddSubReg(llvm::X86::EIP, "EIP", int32_type, reg_type, 0);

  AddReg(llvm::X86::RAX, "RAX", reg_type);
  AddSubReg(llvm::X86::EAX, "EAX", int32_type, reg_type, 0);
  AddSubReg(llvm::X86::AX, "AX", int16_type, int16_type, 0);
  AddSubReg(llvm::X86::AL, "AL", int8_type, int8_type, 0);
  AddSubReg(llvm::X86::AH, "AH", int8_type, int8_type, 1);

  AddReg(llvm::X86::RBX, "RBX", reg_type);
  AddSubReg(llvm::X86::EBX, "EBX", int32_type, reg_type, 0);
  AddSubReg(llvm::X86::BX, "BX", int16_type, int16_type, 0);
  AddSubReg(llvm::X86::BL, "BL", int8_type, int8_type, 0);
  AddSubReg(llvm::X86::BH, "BH", int8_type, int8_type, 1);

  AddReg(llvm::X86::RCX, "RCX", reg_type);
  AddSubReg(llvm::X86::ECX, "ECX", int32_type, reg_type, 0);
  AddSubReg(llvm::X86::CX, "CX", int16_type, int16_type, 0);
  AddSubReg(llvm::X86::CL, "CL", int8_type, int8_type, 0);
  AddSubReg(llvm::X86::CH, "CH", int8_type, int8_type, 1);

  AddReg(llvm::X86::RDX, "RDX", reg_type);
  AddSubReg(llvm::X86::EDX, "EDX", int32_type, reg_type, 0);
  AddSubReg(llvm::X86::DX, "DX", int16_type, int16_type, 0);
  AddSubReg(llvm::X86::DL, "DL", int8_type, int8_type, 0);
  AddSubReg(llvm::X86::DH, "DH", int8_type, int8_type, 1);

  AddReg(llvm::X86::RSI, "RSI", reg_type);
  AddSubReg(llvm::X86::ESI, "ESI", int32_type, reg_type, 0);
  AddSubReg(llvm::X86::SI, "SI", int16_type, int16_type, 0);
  AddSubReg(llvm::X86::SIL, "SIL", int8_type, int8_type, 0);

  AddReg(llvm::X86::RDI, "RDI", reg_type);
  AddSubReg(llvm::X86::EDI, "EDI", int32_type, reg_type, 0);
  AddSubReg(llvm::X86::DI, "DI", int16_type, int16_type, 0);
  AddSubReg(llvm::X86::DIL, "DIL", int8_type, int8_type, 0);

  AddReg(llvm::X86::RSP, "RSP", reg_type);
  AddSubReg(llvm::X86::ESP, "ESP", int32_type, reg_type, 0);
  AddSubReg(llvm::X86::SP, "SP", int16_type, int16_type, 0);
  AddSubReg(llvm::X86::SPL, "SPL", int8_type, int8_type, 0);

  AddReg(llvm::X86::RBP, "RBP", reg_type);
  AddSubReg(llvm::X86::EBP, "EBP", int32_type, reg_type, 0);
  AddSubReg(llvm::X86::BP, "BP", int16_type, int16_type, 0);
  AddSubReg(llvm::X86::BPL, "BPL", int8_type, int8_type, 0);

  AddReg(llvm::X86::R8, "R8", reg_type);
  AddSubReg(llvm::X86::R8D, "R8D", int32_type, reg_type, 0);
  AddSubReg(llvm::X86::R8W, "R8W", int16_type, int16_type, 0);
  AddSubReg(llvm::X86::R8B, "R8B", int8_type, int8_type, 0);

  AddReg(llvm::X86::R9, "R9", reg_type);
  AddSubReg(llvm::X86::R9D, "R9D", int32_type, reg_type, 0);
  AddSubReg(llvm::X86::R9W, "R9W", int16_type, int16_type, 0);
  AddSubReg(llvm::X86::R9B, "R9B", int8_type, int8_type, 0);

  AddReg(llvm::X86::R10, "R10", reg_type);
  AddSubReg(llvm::X86::R10D, "R10D", int32_type, reg_type, 0);
  AddSubReg(llvm::X86::R10W, "R10W", int16_type, int16_type, 0);
  AddSubReg(llvm::X86::R10B, "R10B", int8_type, int8_type, 0);

  AddReg(llvm::X86::R11, "R11", reg_type);
  AddSubReg(llvm::X86::R11D, "R11D", int32_type, reg_type, 0);
  AddSubReg(llvm::X86::R11W, "R11W", int16_type, int16_type, 0);
  AddSubReg(llvm::X86::R11B, "R11B", int8_type, int8_type, 0);

  AddReg(llvm::X86::R12, "R12", reg_type);
  AddSubReg(llvm::X86::R12D, "R12D", int32_type, reg_type, 0);
  AddSubReg(llvm::X86::R12W, "R12W", int16_type, int16_type, 0);
  AddSubReg(llvm::X86::R12B, "R12B", int8_type, int8_type, 0);

  AddReg(llvm::X86::R13, "R13", reg_type);
  AddSubReg(llvm::X86::R13D, "R13D", int32_type, reg_type, 0);
  AddSubReg(llvm::X86::R13W, "R13W", int16_type, int16_type, 0);
  AddSubReg(llvm::X86::R13B, "R13B", int8_type, int8_type, 0);

  AddReg(llvm::X86::R14, "R14", reg_type);
  AddSubReg(llvm::X86::R14D, "R14D", int32_type, reg_type, 0);
  AddSubReg(llvm::X86::R14W, "R14W", int16_type, int16_type, 0);
  AddSubReg(llvm::X86::R14B, "R14B", int8_type, int8_type, 0);

  AddReg(llvm::X86::R15, "R15", reg_type);
  AddSubReg(llvm::X86::R15D, "R15D", int32_type, reg_type, 0);
  AddSubReg(llvm::X86::R15W, "R15W", int16_type, int16_type, 0);
  AddSubReg(llvm::X86::R15B, "R15B", int8_type, int8_type, 0);

  AddReg(llvm::X86::CF, "CF", int8_type);
  AddReg(llvm::X86::PF, "PF", int8_type);
  AddReg(llvm::X86::AF, "AF", int8_type);
  AddReg(llvm::X86::ZF, "ZF", int8_type);
  AddReg(llvm::X86::SF, "SF", int8_type);
  AddReg(llvm::X86::OF, "OF", int8_type);
  AddReg(llvm::X86::DF, "DF", int8_type);

  AddReg(llvm::X86::ST0, "ST0", float80_type);
  AddReg(llvm::X86::ST1, "ST1", float80_type);
  AddReg(llvm::X86::ST2, "ST2", float80_type);
  AddReg(llvm::X86::ST3, "ST3", float80_type);
  AddReg(llvm::X86::ST4, "ST4", float80_type);
  AddReg(llvm::X86::ST5, "ST5", float80_type);
  AddReg(llvm::X86::ST6, "ST6", float80_type);
  AddReg(llvm::X86::ST7, "ST7", float80_type);

  AddReg(llvm::X86::FPU_FLAG_BUSY, "FPU_FLAG_BUSY", int8_type);
  AddReg(llvm::X86::FPU_FLAG_C3, "FPU_FLAG_C3", int8_type);
  AddReg(llvm::X86::FPU_FLAG_C2, "FPU_FLAG_C2", int8_type);
  AddReg(llvm::X86::FPU_FLAG_C1, "FPU_FLAG_C1", int8_type);
  AddReg(llvm::X86::FPU_FLAG_C0, "FPU_FLAG_C0", int8_type);
  AddReg(llvm::X86::FPU_FLAG_ES, "FPU_FLAG_ES", int8_type);
  AddReg(llvm::X86::FPU_FLAG_SF, "FPU_FLAG_SF", int8_type);
  AddReg(llvm::X86::FPU_FLAG_PE, "FPU_FLAG_PE", int8_type);
  AddReg(llvm::X86::FPU_FLAG_UE, "FPU_FLAG_UE", int8_type);
  AddReg(llvm::X86::FPU_FLAG_OE, "FPU_FLAG_OE", int8_type);
  AddReg(llvm::X86::FPU_FLAG_ZE, "FPU_FLAG_ZE", int8_type);
  AddReg(llvm::X86::FPU_FLAG_DE, "FPU_FLAG_DE", int8_type);
  AddReg(llvm::X86::FPU_FLAG_IE, "FPU_FLAG_IE", int8_type);
  AddReg(llvm::X86::FPU_CONTROL_X, "FPU_CONTROL_X", int8_type);
  AddReg(llvm::X86::FPU_CONTROL_RC, "FPU_CONTROL_RC", int8_type);
  AddReg(llvm::X86::FPU_CONTROL_PC, "FPU_CONTROL_PC", int8_type);
  AddReg(llvm::X86::FPU_CONTROL_PM, "FPU_CONTROL_PM", int8_type);
  AddReg(llvm::X86::FPU_CONTROL_UM, "FPU_CONTROL_UM", int8_type);
  AddReg(llvm::X86::FPU_CONTROL_OM, "FPU_CONTROL_OM", int8_type);
  AddReg(llvm::X86::FPU_CONTROL_ZM, "FPU_CONTROL_ZM", int8_type);
  AddReg(llvm::X86::FPU_CONTROL_DM, "FPU_CONTROL_DM", int8_type);
  AddReg(llvm::X86::FPU_CONTROL_IM, "FPU_CONTROL_IM", int8_type);

  AddPadding(int8_type, 10);

  AddReg(llvm::X86::XMM0, "XMM0", int128_type);
  AddReg(llvm::X86::XMM1, "XMM1", int128_type);
  AddReg(llvm::X86::XMM2, "XMM2", int128_type);
  AddReg(llvm::X86::XMM3, "XMM3", int128_type);
  AddReg(llvm::X86::XMM4, "XMM4", int128_type);
  AddReg(llvm::X86::XMM5, "XMM5", int128_type);
  AddReg(llvm::X86::XMM6, "XMM6", int128_type);
  AddReg(llvm::X86::XMM7, "XMM7", int128_type);
  AddReg(llvm::X86::XMM8, "XMM8", int128_type);
  AddReg(llvm::X86::XMM9, "XMM9", int128_type);
  AddReg(llvm::X86::XMM10, "XMM10", int128_type);
  AddReg(llvm::X86::XMM11, "XMM11", int128_type);
  AddReg(llvm::X86::XMM12, "XMM12", int128_type);
  AddReg(llvm::X86::XMM13, "XMM13", int128_type);
  AddReg(llvm::X86::XMM14, "XMM14", int128_type);
  AddReg(llvm::X86::XMM15, "XMM15", int128_type);

  gRegStateStruct = llvm::StructType::create(*context, gRegFields, "RegState", false);
}

const std::string &X86RegisterName(MCSemaRegs reg) {
  const auto it = gRegInfo.find(reg);
  if (it == gRegInfo.end()) {
    std::cerr
        << "ERROR: Can't find register name for number " << reg << std::endl;
    return gBadReg;
  } else {
    return it->second.name;
  }
}

MCSemaRegs X86RegisterNumber(const std::string &name) {
  return gRegNum[name];
}

unsigned X86RegisterOffset(MCSemaRegs reg) {
  const auto it = gRegInfo.find(reg);
  if (it == gRegInfo.end()) {
    std::cerr
        << "ERROR: Can't find register offset for number " << reg << std::endl;
    return 0;
  } else {
    return static_cast<unsigned>(it->second.state_offset);
  }
}

MCSemaRegs X86RegisterParent(MCSemaRegs reg) {
  const auto it = gRegInfo.find(reg);
  if (it == gRegInfo.end()) {
    std::cerr
        << "ERROR: Can't find register parent for number " << reg << std::endl;
    return reg;
  } else {
    return it->second.parent_reg;
  }
}

void X86AllocRegisterVars(llvm::BasicBlock *b) {
  auto func = b->getParent();
  llvm::Argument *state_ptr = &*func->arg_begin();
  auto state_ptr_type = llvm::dyn_cast<llvm::PointerType>(state_ptr->getType());
  auto state_type = state_ptr_type->getElementType();
  llvm::IRBuilder<> ir(b);

  std::unordered_map<MCSemaRegs, llvm::Value *> regs;

  for (const auto &info : gOrderedRegInfo) {
    auto write_var_name = info.name + "_write";
    auto read_var_name = info.name + "_read";

    // Add in the write reg version.
    llvm::Value *write_reg = nullptr;
    if (info.reg == info.parent_reg) {
      write_reg = ir.CreateConstInBoundsGEP2_32(
          state_type, state_ptr, 0, info.state_offset, write_var_name);

    } else if (!info.parent_offset) {
      write_reg = llvm::CastInst::Create(
          llvm::Instruction::BitCast,
          regs[info.parent_reg],
          llvm::PointerType::get(info.write_type, 0),
          write_var_name, b);

    } else {
      auto parent_reg = ir.CreateBitCast(
          regs[info.parent_reg], llvm::PointerType::get(info.write_type, 0), "");
      write_reg = ir.CreateConstInBoundsGEP1_32(
          info.write_type, parent_reg, info.parent_offset, write_var_name);
    }

    // Add in the read register version.
    regs[info.reg] = llvm::CastInst::Create(
        llvm::Instruction::BitCast,
        write_reg,
        llvm::PointerType::get(info.read_type, 0),
        read_var_name, b);
  }
//  b->dump();
//  exit(0);
}

unsigned X86RegisterSize(MCSemaRegs reg) {
  const auto it = gRegInfo.find(reg);
  if (it == gRegInfo.end()) {
    std::cerr
        << "ERROR: Can't find register for number " << reg << std::endl;
    return 0;
  } else {
    return it->second.read_type->getScalarSizeInBits();
  }
}

llvm::StructType *X86RegStateStructType(void) {
  return gRegStateStruct;
}
