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

#pragma once

#include <CFG.pb.h>
#include <CodeObject.h>
#include <glog/logging.h>

#include <string>
#include <unordered_map>
#include <vector>

struct ExternalFunction;

struct MagicSection {
  mcsema::ExternalVariable *WriteExternalVariable(mcsema::Module &module,
                                                  const std::string &name = "");
  mcsema::ExternalFunction *WriteExternalFunction(mcsema::Module &module,
                                                  ExternalFunction &function);

  Dyninst::Address AllocSpace(uint64_t byte_width = 8);

  Dyninst::Address GetAllocated(Dyninst::Address ea);

  bool AllocSpace(Dyninst::Address real, Dyninst::Address original) {
    real_to_imag.insert({real, original});
    return true;
  }

  mcsema::ExternalFunction *GetExternalFunction(Dyninst::Address real_ea) {
    auto ea = real_to_imag.find(real_ea);
    if (ea == real_to_imag.end()) {
      LOG(INFO) << "Addr was not even allocated";
      return nullptr;
    }

    for (auto &func : ext_funcs) {
      if (static_cast<Dyninst::Address>(func->ea()) == ea->second) {
        return func;
      }
    }
    LOG(WARNING) << "Did not find external function in MagicSection despite"
                 << " that addr was allocated";
    return nullptr;
  }

  //TODO(lukas): Rework as ctor
  void init(Dyninst::Address start_ea, int ptr_byte_size = 8) {
    this->start_ea = start_ea;
    this->ptr_byte_size = ptr_byte_size;
  }

  std::string name = "magic_section";
  std::stringstream data;
  Dyninst::Address start_ea = 0;
  uint64_t size = 0;
  int ptr_byte_size = 8;

  std::vector<mcsema::ExternalVariable *> ext_vars;
  std::vector<mcsema::ExternalFunction *> ext_funcs;

  // This will serve when searching for function xrefs, IDA uses everywhere
  // imaginary address while Dyninst catches the .plt stub one
  std::unordered_map<Dyninst::Address, Dyninst::Address> real_to_imag;
};
