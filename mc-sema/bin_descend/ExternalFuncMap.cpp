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
#include <fstream>
#include <iostream>
#include <sstream>

#include "ExternalFuncMap.h"
#include "../common/Defaults.h"

#include <boost/tokenizer.hpp>
#include <boost/foreach.hpp>

#include <algorithm>

using namespace std;

string ExternalFunctionMap::mangleELFSymbol(string inSym, CallingConvention &conv, int &rNumParams) 
{
    return inSym;
}

string ExternalFunctionMap::manglePESymbol(string inSym, CallingConvention &conv, int &rNumParams) 
{
    string outSym = inSym;

    /* COFF objects have this semantic */
    if( outSym.substr(0, strlen("__imp__")) == "__imp__" )
    {
        outSym = outSym.substr(strlen("__imp__"));
    } 
    /* OR this */
    if( outSym.substr(0, strlen("__imp_")) == "__imp_" )
    {
        outSym = outSym.substr(strlen("__imp_"));
    } 

    /* maybe we can learn something about this symbol as is */ 
    else if( outSym.substr(0, strlen("_")) == "_")
    {
        outSym = outSym.substr(strlen("_"));
        // assume sdcall for _<word>
        if (outSym.substr(1, strlen("_")) != "_" ) {
            conv = CalleeCleanup;
        }
    } 
    else if (outSym.substr(0, strlen("@")) == "@")
    {
        outSym = outSym.substr(strlen("@"));
        // assume fastcall for @<word>
        if (outSym.substr(1, strlen("@")) != "@" ) {
            conv = FastCall;
        }
    }

    int atPos = outSym.rfind('@');
    if(atPos >= 0)
    {
        string  strNArgs = outSym.substr(atPos+1, outSym.size());
        istringstream(strNArgs) >> rNumParams;
        rNumParams = rNumParams/4;
        outSym = outSym.substr(0, atPos);
    }

    return outSym;
}

string ExternalFunctionMap::sym_sym(string inSym)
{
  string            outSym = inSym;
  int               rNumParams = -1;
  // if win32, default to CalleeCleanup
  // else default to CallerCleanup

  /* hey, maybe we have the pre-transformed symbol from the sym map
   * and we can avoid touching it
   */
  map<string, ValueElement>::iterator it = this->external_map.find(outSym);
  if(it != this->external_map.end())
  {
      ValueElement  elt = (*it).second;

      if(elt.realName.size() != 0)
      {
          outSym = elt.realName;
      }
      // already done!
      return outSym;
  }
 

  bool is_coff_pe = this->triple.find("win32") != string::npos || 
                 this->triple.find("mingw32") != string::npos;

  CallingConvention conv =  CallerCleanup;
  if( is_coff_pe )
  {
      conv = CalleeCleanup;
      outSym = this->manglePESymbol(outSym, conv, rNumParams);
  } else {
      outSym = this->mangleELFSymbol(outSym, conv, rNumParams);
  }


  /* do we already have a record for this symbol? if we don't, we should add */
  it = this->external_map.find(outSym);
  if(it == this->external_map.end())
  {
    ExternalFunctionMap::ValueElement vk(false, rNumParams, conv, "");
    this->external_map.insert(
      pair<string, ExternalFunctionMap::ValueElement>(outSym, vk));
  }
  else
  {
    ValueElement  elt = (*it).second;

    if(elt.realName.size() != 0)
    {
      outSym = elt.realName;
    }
  }

  return outSym;
}

void ExternalFunctionMap::parseMap(string fileName)
{
  /* open and read in the file given by fileName
   */
  ifstream  inFile(fileName.c_str());

  if(inFile.good() == false) throw LErr(__LINE__, __FILE__, "Cannot open "+fileName);

  while(inFile.good())
  {
    string  line;

    /* lines look like:
     * CreateFileA 8 C
     * exit 1 E Y
     * open 2 E N
     * BaseThreadInitThunk 3 F N
     * !ORDINAL_ws2_32.dll_2:bind 3 E N
     * #comment text
     * DATA: NlsMbCodePageTag 4
     */
    getline(inFile, line, '\n');
    boost::char_separator<char> sep(" ");
    boost::tokenizer<boost::char_separator<char> >  toks(line, sep);
    vector<string>  vtok;
    BOOST_FOREACH(const string &t, toks) { vtok.push_back(t); }
    
    if(vtok.size() >= 3 && vtok[0][0] != '#')
    {
      string            funcName;
      string            realName;
      string 			funcSign = "";
      int               argCount;
      bool              nret = false;

      CallingConvention conv = this->triple.find("win32") != string::npos ? CalleeCleanup : CallerCleanup;

      if(vtok[0] == "DATA:") {
          string dataName = vtok[1];
          int dataSize;

          istringstream(vtok[2]) >> dataSize;

          ExternalFunctionMap::ValueElement dataVK(dataName, dataSize);
          this->external_map.insert(
                  pair<string, ExternalFunctionMap::ValueElement>(dataName, dataVK));
          continue;

      }

      /* read function name */
      funcName = vtok[0];

      /* we might need to split funcName if it contains "!ORDINAL" */
      size_t ordpos = funcName.find("!ORDINAL_");
      if(ordpos != string::npos)
      {
        /* split around the ':' character */
        int atPos = funcName.find(':');
        
        LASSERT(atPos >= 0, "Malformed line in file");

        realName = funcName.substr(atPos+1, funcName.size()); 

        // ensure dll name is capitalized for correct matching
        // as DLLs are case insensitive on windows
        funcName = funcName.substr(1, atPos-1);
        std::transform(funcName.begin(), funcName.end(), funcName.begin(), ::toupper);
      }

      /* read argument count */
      istringstream(vtok[1]) >> argCount;  
      if(argCount < 0) {
          throw LErr(__LINE__, __FILE__, "Could not parse arg count from: " + vtok[1]);
      }

      /* read calling convention */
      char  k = vtok[2][0];
      switch(k) {
        case 'C':
          conv = CallerCleanup;
          break;

        case 'E':
          conv = CalleeCleanup;
          break;

        case 'F':
          conv = FastCall;
          break;

        case 'S':
          conv = X86_64_SysV;
          break;
        case 'W':
          conv = X86_64_Win64;
          break;

        default:
          throw LErr(__LINE__, __FILE__, "Unknown calling convention specification in "+vtok[2]);
      }

      /* is it a noreturn? if nothing, or not-'Y' is there, then no */
      if(vtok.size() >=4 && vtok[3][0] == 'Y')
      {
          nret = true;
      }

      /* function signature (optional)*/
      if(vtok.size() >=5){
    	  funcSign = vtok[4][0];
          printf("function name : %s signature : %s\n", realName.c_str(), funcSign.c_str()), fflush(stdout);
      }


      /* populate map data */
      ExternalFunctionMap::ValueElement vk(nret, argCount, conv, realName, funcSign);
      this->external_map.insert(
        pair<string, ExternalFunctionMap::ValueElement>(funcName, vk));
      if(realName.size() != 0)
      {
        ExternalFunctionMap::ValueElement vk2(nret, argCount, conv, "");
        this->external_map.insert(
          pair<string, ExternalFunctionMap::ValueElement>(realName, vk2));
      }
    }
  }

  return;
}

ExternalFunctionMap::ExternalFunctionMap(string fileName, string tple) : triple(tple)
{
    parseMap(fileName);
}

ExternalFunctionMap::ExternalFunctionMap(string tple) : triple(tple)
{
    return;
}
ExternalFunctionMap::ExternalFunctionMap(void) : triple(DEFAULT_TRIPLE)
{
    return;
}

bool
ExternalFunctionMap::get_calling_convention(string funcName, CallingConvention &c)
{
  map<string,ValueElement>::iterator  it = this->external_map.find(funcName);

  if(it != this->external_map.end() && !it->second.is_data)
  {
    c = (*it).second.conv;
    return true;
  }

  return false;
}

bool
ExternalFunctionMap::get_noreturn(string funcName, bool &r)
{  
  map<string,ValueElement>::iterator  it = this->external_map.find(funcName);

  if(it != this->external_map.end() && !it->second.is_data) {
    r = (*it).second.isNoReturn;
    return true;
  }

  return false;
}

bool
ExternalFunctionMap::get_num_stack_params(string  funcName, int &r)
{  
  map<string,ValueElement>::iterator  it = this->external_map.find(funcName);

  if(it != this->external_map.end() && !it->second.is_data) {
    r = (*it).second.numParams;
    return true;
  }

  return false;
}

bool
ExternalFunctionMap::is_data(const std::string &dn)
{
  map<string,ValueElement>::iterator  it = this->external_map.find(dn);

  if(it != this->external_map.end() && it->second.is_data) {
    return true;
  }

  return false;
}

bool
ExternalFunctionMap::get_data_size(const std::string &dn, int &sz)
{
    map<string,ValueElement>::iterator  it = this->external_map.find(dn);

    if(it != this->external_map.end() && it->second.is_data) {
        sz = it->second.data_size;
        return true;
    }

    return false;
}

bool 
ExternalFunctionMap::get_function_sign(std::string funcName, std::string &funcSign)
{
  map<string,ValueElement>::iterator  it = this->external_map.find(funcName);

  if(it != this->external_map.end() && !it->second.is_data)
  {
    funcSign = (*it).second.funcSign;
    return true;
  }

  return false;
}