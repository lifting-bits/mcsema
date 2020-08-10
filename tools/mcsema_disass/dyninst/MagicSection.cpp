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

#include "MagicSection.h"

#include <glog/logging.h>

#include "ExternalFunctionManager.h"

mcsema::ExternalVariable *
MagicSection::WriteExternalVariable(mcsema::Module &module,
                                    const std::string &name) {
  CHECK(start_ea) << "Magic section cannot start with 0!";

  Dyninst::Address unreal_ea = AllocSpace(ptr_byte_size);

  LOG(INFO) << "External var " << name << " is in magic_section at "
            << unreal_ea;
  auto external_var = module.add_external_vars();
  external_var->set_name(name);
  external_var->set_ea(unreal_ea);

  external_var->set_size(ptr_byte_size);

  //TODO(lukas): This needs some checks
  external_var->set_is_weak(false);
  external_var->set_is_thread_local(false);

  ext_vars.push_back(external_var);

  return external_var;
}

mcsema::ExternalFunction *
MagicSection::WriteExternalFunction(mcsema::Module &module,
                                    ExternalFunction &function) {
  CHECK(start_ea) << "Magic section cannot start with 0!";

  Dyninst::Address unreal_ea = AllocSpace(ptr_byte_size);
  LOG(INFO) << "External function " << function.symbol_name << " at 0x"
            << std::hex << function.ea << " got magic_address at 0x"
            << unreal_ea;
  function.imag_ea = unreal_ea;
  real_to_imag.insert({function.ea, unreal_ea});
  ext_funcs.push_back(function.Write(module));
  return ext_funcs.back();
}

Dyninst::Address MagicSection::AllocSpace(uint64_t byte_width) {
  Dyninst::Address unreal_ea = start_ea + size;
  size += ptr_byte_size;
  for (int i = 0; i < ptr_byte_size; ++i) {
    data << "\0";
  }

  return unreal_ea;
}

Dyninst::Address MagicSection::GetAllocated(Dyninst::Address ea) {
  auto entry = real_to_imag.find(ea);
  if (entry == real_to_imag.end()) {
    LOG(INFO) << "Trying to get magicSection address for not registered ea";
    return 0;
  }
  return entry->second;
}
