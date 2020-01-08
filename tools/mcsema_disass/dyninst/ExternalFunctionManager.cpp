/*
 * Copyright (c) 2018 Trail of Bits, Inc.
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

#include "ExternalFunctionManager.h"

#include <glog/logging.h>

mcsema::ExternalFunction *ExternalFunction::WriteHelper(
    mcsema::Module &module,
    uint64_t ea) {
  auto cfg_external_func = module.add_external_funcs();

  cfg_external_func->set_name(symbol_name);
  cfg_external_func->set_ea(ea);
  cfg_external_func->set_cc(CfgCallingConvention());
  cfg_external_func->set_has_return(has_return);
  cfg_external_func->set_no_return(!has_return);
  cfg_external_func->set_argument_count(arg_count);
  cfg_external_func->set_is_weak(is_weak);

  return cfg_external_func;
}

mcsema::ExternalFunction *ExternalFunction::Write(
    mcsema::Module &module) {
  WriteHelper(module, ea);
  return WriteHelper(module, imag_ea);
}

ExternalFunction::CfgCC ExternalFunction::CfgCallingConvention() const {
  switch (cc) {
    case CallingConvention::CallerCleanup:
      return mcsema::ExternalFunction::CallerCleanup;
    case CallingConvention::CalleeCleanup:
      return mcsema::ExternalFunction::CalleeCleanup;
    default:
      return mcsema::ExternalFunction::FastCall;
  }
}

void ExternalFunctionManager::AddExternalSymbol(const std::string &name,
                                                const ExternalFunction &func) {
  external_funcs[name] = func;
}

void ExternalFunctionManager::AddExternalSymbol(const std::string &s) {
  if (s.empty()) {
    return; // Empty line
  } else if (s.front() == '#') {
    return; // Comment line
  } else if (s.substr(0, 5) == "DATA:") {
    return; // Refers to external data, not a function
  }

  std::string rest = s;
  auto n = rest.find(' ');

  if (n != std::string::npos) {
    std::string symbolName = rest.substr(0, n);
    rest = rest.substr(n + 1);
    n = rest.find(' ');

    if (n != std::string::npos) {
      std::int32_t argCount = std::stoi(rest.substr(0, n));
      rest = rest.substr(n + 1);
      n = rest.find(' ');

      if (n != std::string::npos) {
        char cc = rest.front();
        ExternalFunction::CallingConvention callConv;

        if (cc == 'C') {
          callConv = ExternalFunction::CallingConvention::CallerCleanup;
        } else if (cc == 'E') {
          callConv = ExternalFunction::CallingConvention::CalleeCleanup;
        } else if (cc == 'F') {
          callConv = ExternalFunction::CallingConvention::FastCall;
        } else {
          LOG(FATAL) << "Error while parsing symbol definition \"" << s
                     << "\": unknown calling convention '" << cc << "'"
                     << std::endl;
        }

        rest = rest.substr(n + 1);
        n = rest.find(' ');
        std::string ret;
        Maybe<std::string> signature;

        if (n != std::string::npos) {
          ret = rest.substr(0, 1);
          signature = rest.substr(2);
        } else {
          ret = rest;
        }

        bool noReturn;
        if (ret == "N") {
          noReturn = false;
        } else if (ret == "Y") {
          noReturn = true;
        } else {
          LOG(FATAL) << "Error while parsing symbol definition \"" << s
                     << "\": unknown return type specifier '" << ret << "'"
                     << std::endl;
        }

        bool is_weak = true;

        ExternalFunction func{symbolName, callConv, !noReturn, argCount,
                              is_weak, signature};

        external_funcs[symbolName] = std::move(func);
        return;
      }
    } else {
      LOG(FATAL) << "Internal McSema call convention is no longer supported";
    }
  }

  LOG(FATAL) << "Error while parsing symbol definition \"" << s
             << "\": ill-formed symbol definition" << std::endl;
}

void ExternalFunctionManager::AddExternalSymbols(std::istream &s) {
  std::string line;
  while (std::getline(s, line)) {
    AddExternalSymbol(line);
  }
}

void ExternalFunctionManager::RemoveExternalSymbol(const std::string &name) {
  external_funcs.erase(name);
  used_funcs.erase(name);
}

bool ExternalFunctionManager::IsExternal(const std::string &name) const {
  return external_funcs.find(name) != external_funcs.end();
}

ExternalFunction &
ExternalFunctionManager::GetExternalFunction(const std::string &name) {
  auto external_func = external_funcs.find(name);
  CHECK(external_func != external_funcs.end())
      << "External function " << name << " not found in manager";
  return external_func->second;
}

void ExternalFunctionManager::ClearUsed() { used_funcs.clear(); }

void ExternalFunctionManager::MarkAsUsed(const std::string &name) {
  used_funcs.insert(name);
}

std::vector<ExternalFunction> ExternalFunctionManager::GetAllUsed(
    std::vector<std::string>& unknowns) const {

  std::vector<ExternalFunction> result;

  for (auto name : used_funcs) {
    auto external_func = external_funcs.find(name);
    if (external_func == external_funcs.end()) {
      LOG(INFO) << "External function " << name
                << " not found in file with external definitions";
      result.push_back({name});
      continue;
    }
    result.push_back(external_funcs.at(name));
    unknowns.push_back(name);
  }

  return result;
}
