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
#ifndef _EXTERNAL_FUNC_MAP_H
#define _EXTERNAL_FUNC_MAP_H
#include <string>
#include <map>
#include <LExcn.h>

/* This class represents external functions as known by the overall system.
 * By default, it takes a file with a specific format and constructs a table
 * of facts about external symbols. It supports an interface to query the
 * table for information about calling convention, noreturn, and parameter 
 * count.
 */
class ExternalFunctionMap
{
public:
enum CallingConvention {
  CallerCleanup,
  CalleeCleanup,
  FastCall,
  X86_64_SysV,
  X86_64_Win64
};

private:
  struct  ValueElement {
    bool              isNoReturn;
    int               numParams;
    CallingConvention conv;
    std::string       realName;
    std::string 	  funcSign;
    bool              is_data;
    int               data_size;

    ValueElement(bool b, int n, CallingConvention c, std::string rn, std::string sign) :
      isNoReturn(b), numParams(n), conv(c), realName(rn), is_data(false), data_size(0), funcSign(sign){ }

    ValueElement(bool b, int n, CallingConvention c, std::string rn) :
      isNoReturn(b), numParams(n), conv(c), realName(rn), is_data(false), data_size(0) { }

    ValueElement() : 
        isNoReturn(false), numParams(-1), is_data(false), data_size(0) { }

    ValueElement(const std::string &rn, int sz) :
        realName(rn), isNoReturn(false), numParams(-1), is_data(true), data_size(sz) { }
  };

  std::map<std::string,ValueElement>  external_map;  
protected:
  //llvm::Triple *t_triple;
  std::string triple;
  std::string manglePESymbol(std::string inSym, CallingConvention &conv, int &rNumParams);
  std::string mangleELFSymbol(std::string inSym, CallingConvention &conv, int &rNumParams);


public:
  ExternalFunctionMap(void); // default constructor
  ExternalFunctionMap(std::string); // only target triple
  ExternalFunctionMap(std::string, std::string); // function map, target triple

  bool get_calling_convention(std::string, CallingConvention &);

  bool get_noreturn(std::string, bool &);

  bool get_num_stack_params(std::string, int &);
  std::string  sym_sym(std::string);

  bool is_data(const std::string& en);
  bool get_data_size(const std::string& en, int &sz);
  void parseMap(std::string filename);

  bool get_function_sign(std::string, std::string &);
};
#endif //_EXTERNAL_FUNC_MAP_H
