#include "ExternalFunctionManager.h"

#include <iostream>
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
  if (s.empty())
    return; // Empty line
  else if (s.front() == '#')
    return; // Comment line
  else if (s.substr(0, 5) == "DATA:")
    return; // Refers to external data, not a function

  std::string rest = s;
  int n = rest.find(' ');

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

        if (cc == 'C')
          callConv = ExternalFunction::CallingConvention::CallerCleanup;
        else if (cc == 'E')
          callConv = ExternalFunction::CallingConvention::CalleeCleanup;
        else if (cc == 'F')
          callConv = ExternalFunction::CallingConvention::FastCall;
        else {
          std::cerr << "Error while parsing symbol definition \"" << s
                    << "\": unknown calling convention '" << cc << "'"
                    << std::endl;
          LOG(FATAL) << "Error while parsing symbol definition";
        }

        rest = rest.substr(n + 1);
        n = rest.find(' ');
        std::string ret;
        std::experimental::optional<std::string> signature;

        if (n != std::string::npos) {
          ret = rest.substr(0, 1);
          signature = rest.substr(2);
        } else
          ret = rest;

        bool noReturn;
        if (ret == "N")
          noReturn = false;
        else if (ret == "Y")
          noReturn = true;
        else {
          std::cerr << "Error while parsing symbol definition \"" << s
                    << "\": unknown return type specifier '" << noReturn << "'"
                    << std::endl;
          LOG(FATAL) << "Error while parsing symbol definition";
        }

        bool is_weak = true;
        if (symbolName == "__gmon_start__") {
          is_weak = true;
        }
        ExternalFunction func{symbolName, callConv, !noReturn, argCount,
                              is_weak, signature};

        external_funcs[symbolName] = func;
        return;
      }
    } else {
      LOG(FATAL) << "Internal McSema call convention is no longer supported";
    }
  }

  std::cerr << "Error while parsing symbol definition \"" << s
            << "\": ill-formed symbol definition" << std::endl;

  LOG(FATAL) << "Error while parsing symbol definition";
}

void ExternalFunctionManager::AddExternalSymbols(std::istream &s) {
  while (!s.eof()) {
    std::string line;
    std::getline(s, line);
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
  return external_funcs.at(name);
}

void ExternalFunctionManager::ClearUsed() { used_funcs.clear(); }

void ExternalFunctionManager::MarkAsUsed(const std::string &name) {
  used_funcs.insert(name);
}

std::vector<ExternalFunction> ExternalFunctionManager::GetAllUsed(
    std::vector<std::string>& unknowns) const {

  std::vector<ExternalFunction> result;

  for (auto name : used_funcs) {
    try {
      result.push_back(external_funcs.at(name));
    } catch (const std::out_of_range &oor) {
      unknowns.push_back(name);
    }
  }

  return result;
}
