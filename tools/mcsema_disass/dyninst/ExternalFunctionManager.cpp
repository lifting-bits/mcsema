#include "ExternalFunctionManager.h"
#include <iostream>

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

void ExternalFunctionManager::addExternalSymbol(const std::string &name,
                                                const ExternalFunction &func) {
  external_funcs[name] = func;
}

void ExternalFunctionManager::addExternalSymbol(const std::string &s) {
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
          throw std::runtime_error{"error while parsing symbol definition"};
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
          throw std::runtime_error{"error while parsing symbol definition"};
        }

        ExternalFunction func{symbolName, callConv, !noReturn, argCount,
                          false /* TODO? */, signature};

        external_funcs[symbolName] = func;
        return;
      }
    } else {
      throw std::runtime_error{
          "internal McSema call convention is no longer supported"};
    }
  }

  std::cerr << "Error while parsing symbol definition \"" << s
            << "\": ill-formed symbol definition" << std::endl;

  throw std::runtime_error{"error while parsing symbol definition"};
}

void ExternalFunctionManager::addExternalSymbols(std::istream &s) {
  while (!s.eof()) {
    std::string line;
    std::getline(s, line);
    addExternalSymbol(line);
  }
}

void ExternalFunctionManager::removeExternalSymbol(const std::string &name) {
  external_funcs.erase(name);
  used_funcs.erase(name);
}

bool ExternalFunctionManager::isExternal(const std::string &name) const {
  return external_funcs.find(name) != external_funcs.end();
}

const ExternalFunction &
ExternalFunctionManager::getExternalFunction(const std::string &name) {
  return external_funcs.at(name);
}

void ExternalFunctionManager::clearUsed() { used_funcs.clear(); }

void ExternalFunctionManager::markAsUsed(const std::string &name) {
  used_funcs.insert(name);
}

std::vector<ExternalFunction> ExternalFunctionManager::getAllUsed(
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
