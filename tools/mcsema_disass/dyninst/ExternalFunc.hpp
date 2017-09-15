#pragma once

#include <cstdint>
#include <experimental/optional>
#include <CFG.pb.h>

class ExternalFunc
{
public:
    bool operator< (const ExternalFunc& other) const { return m_symbolName < other.m_symbolName; }

    enum class CallingConvention
    {
        CallerCleanup = 0,
        CalleeCleanup = 1,
        FastCall = 2
    };

    ExternalFunc () = default;
    ExternalFunc (const std::string& symbolName,
                  CallingConvention callConv,
                  bool hasReturn,
                  bool noReturn,
                  std::int32_t argCount,
                  bool isWeak,
                  const std::experimental::optional<std::string>& signature = {});

    const std::string& symbolName () const;
    CallingConvention callingConvention () const;
    mcsema::ExternalFunction::CallingConvention cfgCallingConvention () const;
    bool hasReturn () const;
    bool noReturn () const;
    std::int32_t argumentCount () const;
    bool isWeak () const;
    const std::experimental::optional<std::string>& signature () const;

    void setSymbolName (const std::string& name);
    void setCallingConvention (CallingConvention cc);
    void setHasReturn (bool hasReturn);
    void setNoReturn (bool noReturn);
    void setArgumentCount (std::int32_t argCount);
    void setIsWeak (bool isWeak);
    void setSignature (const std::experimental::optional<std::string>& signature);

private:
    std::string m_symbolName;
    CallingConvention m_callConv;
    bool m_hasReturn;
    bool m_noReturn;
    std::int32_t m_argCount;
    bool m_isWeak;
    std::experimental::optional<std::string> m_signature;
};
