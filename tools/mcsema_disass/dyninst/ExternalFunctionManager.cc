#include "ExternalFunctionManager.hpp"
#include <iostream>

void ExternalFunctionManager::addExternalSymbol(const std::string &name,
                                                const ExternalFunc &func) {
  m_extFuncs[name] = func;
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
        ExternalFunc::CallingConvention callConv;

        if (cc == 'C')
          callConv = ExternalFunc::CallingConvention::CallerCleanup;
        else if (cc == 'E')
          callConv = ExternalFunc::CallingConvention::CalleeCleanup;
        else if (cc == 'F')
          callConv = ExternalFunc::CallingConvention::FastCall;
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

        ExternalFunc func(symbolName, callConv, !noReturn, noReturn, argCount,
                          false /* TODO? */, signature);

        m_extFuncs[symbolName] = func;
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
  m_extFuncs.erase(name);
  m_usedFuncs.erase(name);
}

bool ExternalFunctionManager::isExternal(const std::string &name) const {
  return m_extFuncs.find(name) != m_extFuncs.end();
}

const ExternalFunc &
ExternalFunctionManager::getExternalFunction(const std::string &name) {
  return m_extFuncs.at(name);
}

void ExternalFunctionManager::clearUsed() { m_usedFuncs.clear(); }

void ExternalFunctionManager::markAsUsed(const std::string &name) {
  m_usedFuncs.insert(name);
}

std::set<ExternalFunc> ExternalFunctionManager::getAllUsed( std::vector<std::string>& unknowns) const {
  std::set<ExternalFunc> result;

  for (auto name : m_usedFuncs) {
    try {
      result.insert(m_extFuncs.at(name));
    } catch (const std::out_of_range &oor) {
      unknowns.push_back(name);
    }
  }

  return result;
}
