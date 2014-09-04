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
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/ADT/OwningPtr.h"
#include "llvm/ADT/Triple.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/MemoryObject.h"
#include "llvm/Object/COFF.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/system_error.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/DataTypes.h"
#include "llvm/Support/Debug.h"
#include "cfg_recover.h"
#include <bincomm.h>
#include <peToCFG.h>
#include <LExcn.h>
#include <iostream>
#include <sstream>
#include <boost/filesystem.hpp>
#include "../common/to_string.h"

#include "../common/Defaults.h"

using namespace std;
using namespace boost;
using namespace llvm;

//command line options 
cl::opt<string>
InputFilename("i", cl::desc("Input filename"), cl::value_desc("filename"));

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
  LLVMByteDecoder         byteDec;

  if(EntryPoint.size()) {
      for(unsigned i = 0; i < EntryPoint.size(); i++) {
          //get the entry point from the command line 
          ::uint64_t      tmp = 0;
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
    list<pair<string, boost::uint64_t> > tmp;
    exc->get_exports(tmp);

    for(list<pair<string, boost::uint64_t> >::iterator it = tmp.begin(), e = tmp.end();
        it != e;
        ++it)
    {
      entrySymbols.push_back(
              NativeModule::EntrySymbol(
                  it->first,
                  it->second));
      entryPoints.push_back(it->second);
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
  for(list<boost::uint64_t>::iterator it = entryPoints.begin(), e = entryPoints.end();
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

  //sanity
  if(EntrySymbol.size() == 0 && EntryPoint.size() == 0) {
    //One of these must be set
    llvm::errs() << "Must specify at least one entry point via -entry-symbol or -e\n";
    return -1;
  }

  ExternalFunctionMap funcs(TargetTriple);
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

  //make an LLVM target that is appropriate
  const Target  *x86Target = NULL;
  for(TargetRegistry::iterator it = TargetRegistry::begin(),
        e = TargetRegistry::end();
      it != e;
      ++it)
  {
    const Target  &t = *it;

    if(string(t.getName()) == "x86") {
      x86Target = &t;
      break;
    }
  }

  if(InputFilename == "") {
      errs() << "Invalid arguments.\nUse :'" << argv[0] << " -help' for help\n";
      return -1;
  }

  //open the binary input file
  ExecutableContainer *exc = NULL;
  
  try {
      exc = ExecutableContainer::open(InputFilename, x86Target);
  } catch (LErr &l) {
      errs() << "Could not open: " << InputFilename << ", reason: " << l.what() << "\n";
      return -1;
  } catch (...) {
      errs() << "Could not open: " << InputFilename << "\n";
      return -1;
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
        //write out to file, but, make the file name 
        //the same as the input file name with the ext
        //removed and replaced with .cfg
        filesystem::path  p = filesystem::path(string(InputFilename));
        p = p.replace_extension(".cfg");
        
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
