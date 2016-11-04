/*
Copyright (c) 2014, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of Trail of Bits nor the names of its
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
#ifndef _EXTERNALS_H
#define _EXTERNALS_H
#include <boost/shared_ptr.hpp>
#include <boost/cstdint.hpp>
#include <string>
using boost::int8_t;

class ExternalRef {

public:
    ExternalRef(const std::string &sn): symbolName(sn) {};
    virtual std::string getSymbolName(void) { return this->symbolName; }
    virtual void setWeak(bool w) { this->weak = w; }
    virtual bool isWeak(void) { return this->weak; }
    virtual ~ExternalRef() {};

protected:
    std::string symbolName;
    bool        weak;
};

class ExternalDataRef : public ExternalRef {
    
    protected:
        size_t dataSize;


    public:
        
    ExternalDataRef(const std::string &name): dataSize(0), ExternalRef(name)
    {
    }
    ExternalDataRef(const std::string &name, size_t dtsz) : dataSize(dtsz), ExternalRef(name)
    { 
        // empty constructor
    }

    void setDataSize(size_t newsize) { this->dataSize = newsize; }
    size_t getDataSize() { return this->dataSize; }

};

class ExternalCodeRef : public ExternalRef {
public:
    enum CallingConvention {
        CallerCleanup,
        CalleeCleanup,
        FastCall,
        X86_64_SysV,
        X86_64_Win64,
        McsemaCall
    };

    enum ReturnType {
        Unknown,
        VoidTy,
        IntTy,
        NoReturn
    };

    int8_t getNumArgs(void) { return this->numArgs; }
    ReturnType getReturnType(void) { return this->ret; }
    CallingConvention getCallingConvention(void) { return this->conv; }

    void setReturnType(ReturnType r) { this->ret = r; }

    std::string getFunctionSignature(void) { return this->funcSign; }

    ExternalCodeRef(const std::string &fn, int8_t d, CallingConvention c, ReturnType r, const std::string &sign) :
                                            numArgs(d),
                                            conv(c),
                                            ret(r), ExternalRef(fn), funcSign(sign) { }

    ExternalCodeRef(const std::string &fn, int8_t d, CallingConvention c, ReturnType r) :
                                            numArgs(d),
                                            conv(c),
                                            ret(r), ExternalRef(fn), funcSign("") { }

    ExternalCodeRef(const std::string &fn, int8_t d, CallingConvention c) :  
                                            numArgs(d),
                                            conv(c),
                                            ret(Unknown), ExternalRef(fn), funcSign("") { }

    ExternalCodeRef(const std::string &fn, int8_t d) :  numArgs(d),
                                            conv(CallerCleanup),
                                            ret(Unknown), ExternalRef(fn), funcSign("") { }

    ExternalCodeRef(const std::string &fn) :    numArgs(-1),
                                    conv(CallerCleanup),
                                    ret(Unknown), ExternalRef(fn), funcSign("") { }

protected:

    int8_t              numArgs;
    CallingConvention   conv;
    ReturnType          ret;
    std::string         funcSign;
};

typedef boost::shared_ptr<ExternalCodeRef> ExternalCodeRefPtr;
typedef boost::shared_ptr<ExternalDataRef> ExternalDataRefPtr;

#endif
