/*
Copyright (c) 2017, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of the organization nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <glog/logging.h>

#include <string>

#include <llvm/IR/Constants.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Util.h"

namespace mcsema {

llvm::LLVMContext *gContext = nullptr;
llvm::Module *gModule = nullptr;

//// Return a constnat integer of width `width` and value `val`.
//llvm::ConstantInt *CreateConstantInt(int width, uint64_t val) {
//  auto bTy = llvm::Type::getIntNTy(*gContext, width);
//  return llvm::ConstantInt::get(bTy, val);
//}

// Return the type of a lifted function.
llvm::FunctionType *LiftedFunctionType(void) {
  static llvm::FunctionType *func_type = nullptr;
  if (!func_type) {
    func_type = gModule->getFunction("__remill_basic_block")->getFunctionType();
  }
  return func_type;
}

//static llvm::Constant *GetPointerSizedValue(
//    llvm::Module *M, llvm::Constant *v, int valsize) {
//  auto final_val = v;
//  if (ArchPointerSize(M) == valsize) {
//    return v;
//
//  } else if (ArchPointerSize(M) == Pointer64 && valsize == 4) {
//    auto int_val = llvm::ConstantExpr::getPtrToInt(
//        v, llvm::Type::getInt64Ty(M->getContext()));
//    final_val = llvm::ConstantExpr::getTrunc(
//        int_val, llvm::Type::getInt32Ty(M->getContext()));
//  }
//
//  return final_val;
//}
//
//static llvm::GlobalVariable *GetSectionForDataAddr(
//    const std::list<DataSection> &dataSecs, llvm::Module *M, uint64_t data_addr,
//    uint64_t &section_base) {
//
//  for (auto &dt : dataSecs) {
//    uint64_t start = dt.getBase();
//    uint64_t end = start + dt.getSize();
//
//    if (data_addr >= start && data_addr < end) {
//      std::stringstream ss;
//      ss << "data_" << std::hex << start;
//      section_base = start;
//      return M->getNamedGlobal(ss.str());
//    }
//  }
//  return nullptr;
//}
//
//static llvm::Constant *CreateConstantBlob(llvm::LLVMContext &ctx,
//                                    const std::vector<uint8_t> &blob) {
//  auto charTy = llvm::Type::getInt8Ty(ctx);
//  auto arrT = llvm::ArrayType::get(charTy, blob.size());
//  std::vector<llvm::Constant *> array_elements;
//  for (auto cur : blob) {
//    auto c = llvm::ConstantInt::get(charTy, cur);
//    array_elements.push_back(c);
//  }
//  return llvm::ConstantArray::get(arrT, array_elements);
//}
//
//void dataSectionToTypesContents(NativeModulePtr natM,
//                                const std::list<DataSection> &globaldata,
//                                const DataSection &ds, llvm::Module *M,
//                                std::vector<llvm::Constant *> &secContents,
//                                std::vector<llvm::Type *> &data_section_types,
//                                bool convert_to_callback) {
//  // find what elements will be needed for this data section
//  // There are three main types:
//  // Functions: pointer to a known function in the cfg
//  // Data Symbol: pointer to another data section item
//  // Blob: opaque data treated as byte array
//  //
//  // The final data structure will look something like
//  // struct data_section {
//  //  function f1,
//  //  function f2,
//  //  uint8_t blob0[100];
//  //  datasymbol d0;
//  //  uint8_t blob1[200];
//  //  ....
//  //  };
//  //
//  const auto &ds_entries = ds.getEntries();
//  for (auto &data_sec_entry : ds_entries) {
//    std::string sym_name;
//
//    if (data_sec_entry.getSymbol(sym_name)) {
//
//      LOG(INFO)
//          << ": Found symbol: " << sym_name << " in "
//          << std::hex << data_sec_entry.getBase();
//
//      if (sym_name.find("ext_") == 0) {
//
//        // TODO(pag): this is flaky!
//        auto ext_sym_name = sym_name.c_str() + 4 /* strlen("ext_") */;
//
//        llvm::Constant *final_val = nullptr;
//        auto ext_v = M->getNamedValue(ext_sym_name);
//
//        if (ext_v != nullptr && llvm::isa<llvm::Function>(ext_v)) {
//          final_val = GetPointerSizedValue(M, ext_v, data_sec_entry.getSize());
//
//        } else if (ext_v != nullptr) {
//          final_val = GetPointerSizedValue(M, ext_v, data_sec_entry.getSize());
//
//        // assume ext data
//        } else {
//          CHECK(ext_v != nullptr)
//              << "Could not find external: " << ext_sym_name;
//        }
//
//        secContents.push_back(final_val);
//        data_section_types.push_back(final_val->getType());
//
//      } else if (sym_name.find("sub_") == 0) {
//        // TODO(pag): This is so flaky.
//        auto sub_addr_str = sym_name.c_str() + 4 /* strlen("sub_") */;
//        uint64_t sub_addr = 0;
//        sscanf(sub_addr_str, "%lx", &sub_addr);
//
//        const auto &funcs = natM->get_funcs();
//        auto func_it = funcs.find(sub_addr);
//
//        CHECK(func_it != funcs.end())
//            << "Could not find function associated with symbol "
//            << sym_name << " at address " << std::hex << sub_addr
//            << " in data section entry.";
//
//        // add function pointer to data section
//        // to do this, create a callback driver for
//        // it first (since it may be called externally)
//
//        auto natF = func_it->second;
//        auto func_name = natF->get_name();
//        auto func = M->getFunction(func_name);
//        CHECK(func != nullptr)
//            << "Could not find function" << func_name << "(" << sym_name
//            << " in the data section entry)";
//
//        if (convert_to_callback) {
//          func = ArchAddCallbackDriver(func);
//          CHECK(func != nullptr)
//              << "Could make callback for " << func_name
//              << " at address " << std::hex << sub_addr << " ("
//              << sym_name << " in the data section entry)";
//        }
//
//        auto final_val = GetPointerSizedValue(
//            M, func, data_sec_entry.getSize());
//        secContents.push_back(final_val);
//        data_section_types.push_back(final_val->getType());
//
//      } else if (sym_name.find("data_") == 0) {
//
//        // TODO(pag): This is so flaky.
//        auto data_addr_str = sym_name.c_str() + 5 /* strlen("data_") */;
//        uint64_t data_addr = 0;
//        sscanf(data_addr_str, "%lx", &data_addr);
//
//        // data symbol
//        // get the base of the data section for this symobol
//        // then compute the offset from base of data
//        // and store as integer value of (base+offset)
//        uint64_t section_base;
//        auto g_ref = GetSectionForDataAddr(globaldata, M, data_addr,
//                                           section_base);
//        CHECK(g_ref != nullptr)
//            << "Could not get data addr for:" << data_addr_str;
//
//        // instead of referencing an element directly
//        // we just convert the pointer to an integer
//        // and add its offset from the base of data
//        // to the new data section pointer
//        uint64_t addr_diff = data_addr - section_base;
//        llvm::Constant *final_val = nullptr;
//
//        if (ArchPointerSize(M) == Pointer32) {
//          auto int_val = llvm::ConstantExpr::getPtrToInt(
//              g_ref, llvm::Type::getInt32Ty(M->getContext()));
//          final_val = llvm::ConstantExpr::getAdd(
//              int_val, CONST_V_INT<32>(M->getContext(), addr_diff));
//        } else {
//          auto int_val = llvm::ConstantExpr::getPtrToInt(
//              g_ref, llvm::Type::getInt64Ty(M->getContext()));
//          final_val = llvm::ConstantExpr::getAdd(
//              int_val, CONST_V_INT<64>(M->getContext(), addr_diff));
//        }
//        secContents.push_back(final_val);
//        data_section_types.push_back(final_val->getType());
//
//      } else {
//        LOG(FATAL)
//            << "Unknown data section entry symbol type " << sym_name;
//      }
//    } else {
//      // add array
//      // this holds opaque data in a byte array
//      auto arr = CreateConstantBlob(M->getContext(), data_sec_entry.getBytes());
//      secContents.push_back(arr);
//      data_section_types.push_back(arr->getType());
//    }  // if dsec_itr
//  }  // for list
//}

}  // namespace mcsema
