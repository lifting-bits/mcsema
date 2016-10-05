/*
Copyright (c) 2013, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of the {organization} nor the names of its
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
#include <string>
#include "llvm/ADT/Triple.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/DataTypes.h"
#include "llvm/Support/Debug.h"
#include "cfg_recover.h"
#include <bincomm.h>
#include <peToCFG.h>
#include <LExcn.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <boost/filesystem.hpp>
#include "../common/to_string.h"
#include "../common/Defaults.h"

using namespace std;
using namespace boost;
using namespace llvm;

//command line options 
cl::opt<string>
InputFilename("i", cl::desc("Input filename"), cl::value_desc("filename"));

cl::opt<string>
OutputFilename("o", cl::desc("Output filename"), cl::value_desc("filename"));

cl::opt<string>
PriorKnowledge("p", cl::desc("Proto buffer containing prior knowldege"), cl::value_desc("filename"));

cl::opt<string>
SystemArch("march", cl::desc("Target description"), cl::value_desc("architecture"));

cl::opt<int>
Verbosity("v", cl::desc("Verbosity level"), cl::value_desc("level"));

cl::list<string>
EntryPoint("e", cl::desc("Entry point"), cl::value_desc("VA"));

cl::list<string>
FuncMap("func-map", 
        cl::CommaSeparated, 
        cl::desc("Function map files"), 
        cl::value_desc("std_defs.txt,custom_defs.txt,other_mapping.txt"));

cl::opt<bool>
IgnoreNativeEntryPoints("ignore-native-entry-points",
                        cl::desc("Ignore any exported functions not explicitly specified via -e or -entry-symbol"),
                        cl::init(true));

cl::opt<bool>
DebugMode("d",
          cl::desc("Print debug information"),
          cl::init(false));

cl::list<string>
EntrySymbol("entry-symbol",
            cl::CommaSeparated, 
            cl::desc("Entry point symbol"),
            cl::value_desc("symbol1,symbol2,symbol3,..."));

cl::opt<string>
TargetTriple("mtriple", cl::desc("Target Triple"), cl::value_desc("target triple"), cl::init(DEFAULT_TRIPLE));


NativeModulePtr makeNativeModule( ExecutableContainer *exc, 
                                  ExternalFunctionMap &funcs) 
{
  // these entry points are valid function entry points, but
  // they will not be externally visible
  list<VA>          entryPoints;

  // these will be externally visible
  vector<NativeModule::EntrySymbol>     entrySymbols;

  list<NativeFunctionPtr> recoveredFuncs;
  LLVMByteDecoder         byteDec(exc->target);

  if(EntryPoint.size()) {
      for(unsigned i = 0; i < EntryPoint.size(); i++) {
          //get the entry point from the command line 
          std::uint64_t      tmp = 0;
          std::string ep = EntryPoint[i];
          stringstream  ss;
          if(ep.size() > 2 && ep[0] == '0' && ep[1] == 'x') {
              ss << hex << ep;
          } else {
              ss << ep;
          }

          ss >> tmp;
          entryPoints.push_back(((VA)tmp));
          entrySymbols.push_back(NativeModule::EntrySymbol(tmp));
      }
  }

  if(EntrySymbol.size()) {
      //have to look this symbol up from the ExecutableContainer
      list<pair<string, VA> > t;
      if(!exc->get_exports(t)) {
          throw LErr(__LINE__, __FILE__, "Could not parse export table");
      }

      for(unsigned i = 0; i < EntrySymbol.size(); i++) {

          std::string es = EntrySymbol[i];

          for(list<pair<string, VA> >::iterator it = t.begin(), e = t.end();
                  it != e;
                  ++it)
          {
              if(it->first == es) {
                  entryPoints.push_back(it->second);
                  entrySymbols.push_back(
                          NativeModule::EntrySymbol(
                              it->first,
                              it->second));
                  break;
              }
          }
      }
  }

  if(IgnoreNativeEntryPoints == false) {
      //get entry points from the file too
      list<pair<string, std::uint64_t> > tmp;
      exc->get_exports(tmp);

      for(list<pair<string, std::uint64_t> >::iterator it = tmp.begin(), e = tmp.end();
              it != e;
              ++it)
      {
          entrySymbols.push_back(
                  NativeModule::EntrySymbol(
                      it->first,
                      it->second));
          entryPoints.push_back(it->second);
      }

      std::uint64_t file_ep;
      if(exc->getEntryPoint(file_ep)) {
          entryPoints.push_back(file_ep);
      }
  }


  if(entryPoints.size() == 0) {
    throw LErr(__LINE__, __FILE__, "No good entry points found or supplied");
  }

  if(DebugMode) {
      addDataEntryPoints(exc, entryPoints, llvm::dbgs());
  } else {
      addDataEntryPoints(exc, entryPoints, nulls());
  }

  set<VA> visited;
  //now, get functions for these entry points with this executable 
  //context
  outs() << "We have " << entryPoints.size() << " entry points\n";

  for(list<std::uint64_t>::iterator it = entryPoints.begin(), e = entryPoints.end();
      it != e;
      ++it)
  {
    list<NativeFunctionPtr> tmp;
    if(DebugMode) {
      tmp = getFuncs(exc, byteDec, visited, *it, funcs, llvm::dbgs());
    } else {
      tmp = getFuncs(exc, byteDec, visited, *it, funcs, nulls());
    }

    recoveredFuncs.insert(recoveredFuncs.end(), tmp.begin(), tmp.end());

  }

  //add the recovered functions to a new NativeModule
  NativeModulePtr m(new NativeModule(exc->name(), recoveredFuncs, NULL));

  // add exported entry points
  for(vector<NativeModule::EntrySymbol>::const_iterator it_es = entrySymbols.begin();
          it_es != entrySymbols.end();
          it_es++) 
  {
      m->addEntryPoint(*it_es);
  }

  //add what data we can discern is required to m
  //data is required if it is a data section from exc
  vector<ExecutableContainer::SectionDesc>  secs;
  if(!exc->get_sections(secs)) throw LErr(__LINE__, __FILE__, "Sections");
  for(vector<ExecutableContainer::SectionDesc>::iterator it = secs.begin(),
      e = secs.end();
      it != e;
      ++it)
  {
    ExecutableContainer::SectionDesc  s = *it;
    
    if(s.type == ExecutableContainer::DataSection) {
      //add to m
      DataSection ds = processDataSection(exc, s);
      // make sure data section is not empty
      if(ds.getBase() != DataSection::NO_BASE) {
          outs() << "Adding data section: " 
              << to_string<VA>(ds.getBase(), hex) << " - "
              << to_string<VA>(ds.getBase()+ds.getSize(), hex) << "\n";
          ds.setReadOnly(s.read_only);
          m->addDataSection(ds);
      }
    }
  }

  //add the external function references
  addExterns(recoveredFuncs, m);

  //done
  return m;
}

void printVersion(void) {
  llvm::outs() << "0.1\n";
  return;
}

int main(int argc, char *argv[]) {
  //command line arguments
  cl::SetVersionPrinter(printVersion);
  cl::ParseCommandLineOptions(argc, argv, "binary recursive descent");

  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();
  llvm::Triple *triple;

  //make an LLVM target that is appropriate
  const Target  *x86Target = NULL;
  for(TargetRegistry::iterator it = TargetRegistry::begin(),
        e = TargetRegistry::end();
      it != e;
      ++it)
  {
    const Target  &t = *it;
    if(string(t.getName()) == SystemArch) {
      x86Target = &t;
      break;
    }
  }  

  if(!SystemArch.compare("x86-64")){
	  triple = new Triple(DEFAULT_TRIPLE_X64);
  } else {
	  triple = new Triple(DEFAULT_TRIPLE);
  }

  ExternalFunctionMap funcs(triple->getTriple());

  try {

      if(FuncMap.size()) {
          for(unsigned i = 0; i < FuncMap.size(); ++i) {
              funcs.parseMap(FuncMap[i]);
          }
      }
  } catch (LErr &l){
      cerr << "Exception while parsing external map:\n" 
          << l.what() << std::endl;
      return -2;
  }

  if(InputFilename == "") {
      errs() << "Invalid arguments.\nUse :'" << argv[0] << " -help' for help\n";
      return -1;
  }

  if(PriorKnowledge == "") {
      outs() << "Disassembly not guided by outside facts.\nUse :'" << argv[0] << "-p <protobuff>' to feed information to guide the disassembly\n";
  }


  //open the binary input file
  ExecutableContainer *exc = NULL;
  
  
  try {
    exc = ExecutableContainer::open(InputFilename, x86Target, PriorKnowledge);
  } catch (LErr &l) {
      errs() << "Could not open: " << InputFilename << ", reason: " << l.what() << "\n";
      return -1;
  } catch (...) {
      errs() << "Could not open: " << InputFilename << "\n";
      return -1;
  }

  //sanity
  if(EntrySymbol.size() == 0 && EntryPoint.size() == 0) {
      std::uint64_t file_ep;
      // maybe this file format specifies an entry point?
      if(false == exc->getEntryPoint(file_ep)) {
          //We don't know which entry point to use!
          llvm::errs() << "Could not identify an entry point for: [" << InputFilename << "].\n";
          llvm::errs() << "You must manually specify at least one entry point. Use either -entry-symbol or -e.\n";
          return -1;
      }
  }


  if(exc->is_open()) {
    //convert to native CFG
    NativeModulePtr m;
    try{
      m = makeNativeModule(exc, funcs);
    } catch(LErr &l) {
      outs() << "Failure to make module: " << l.what() << "\n";
      return -1;
    }

    if(m) {
      //write out to protobuf 
      string  outS = dumpProtoBuf(m);
      if(outS.size() > 0) {
        filesystem::path p;
        if (OutputFilename == "") {
            //write out to file, but, make the file name
            //the same as the input file name with the ext
            //removed and replaced with .cfg
            p = filesystem::path(string(InputFilename));
            p = p.replace_extension(".cfg");
        }
        else {
            p = filesystem::path(string(OutputFilename));
        }

        FILE  *out = fopen(p.string().c_str(), "wb");
        if(out) {
          fwrite(outS.c_str(), 1, outS.size(), out);
          fclose(out);
        } else {
          //report error
          outs() << "Could not open " << p.string() << "\n";
        }
      }
    }

  } else {
    outs() << "Could not open executable module " << InputFilename << "\n";
  }

  return 0;
}
