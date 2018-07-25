#include "ExternalFunc.h"

ExternalFunc::ExternalFunc(
    const std::string &symbolName, CallingConvention callConv, bool hasReturn,
    bool noReturn, std::int32_t argCount, bool isWeak,
    const std::experimental::optional<std::string> &signature)
    : m_symbolName(symbolName), m_callConv(callConv), m_hasReturn(hasReturn),
      m_noReturn(noReturn), m_argCount(argCount), m_isWeak(isWeak),
      m_signature(signature) {}

const std::string &ExternalFunc::symbolName() const { return m_symbolName; }

ExternalFunc::CallingConvention ExternalFunc::callingConvention() const {
  return m_callConv;
}

mcsema::ExternalFunction::CallingConvention
ExternalFunc::cfgCallingConvention() const {
  switch (callingConvention()) {
  case CallingConvention::CallerCleanup:
    return mcsema::ExternalFunction::CallerCleanup;
  case CallingConvention::CalleeCleanup:
    return mcsema::ExternalFunction::CalleeCleanup;
  default:
    return mcsema::ExternalFunction::FastCall;
  }
}

bool ExternalFunc::hasReturn() const { return m_hasReturn; }

bool ExternalFunc::noReturn() const { return m_noReturn; }

std::int32_t ExternalFunc::argumentCount() const { return m_argCount; }

bool ExternalFunc::isWeak() const { return m_isWeak; }

const std::experimental::optional<std::string> &
ExternalFunc::signature() const {
  return m_signature;
}

void ExternalFunc::setSymbolName(const std::string &name) {
  m_symbolName = name;
}

void ExternalFunc::setCallingConvention(CallingConvention cc) {
  m_callConv = cc;
}

void ExternalFunc::setHasReturn(bool hasReturn) { m_hasReturn = hasReturn; }

void ExternalFunc::setNoReturn(bool noReturn) { m_noReturn = noReturn; }

void ExternalFunc::setArgumentCount(std::int32_t argCount) {
  m_argCount = argCount;
}

void ExternalFunc::setIsWeak(bool isWeak) { m_isWeak = isWeak; }

void ExternalFunc::setSignature(
    const std::experimental::optional<std::string> &signature) {
  m_signature = signature;
}
