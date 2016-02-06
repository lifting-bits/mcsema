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
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCSubtargetInfo.h"
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
#include "llvm/Support/TargetSelect.h"
#include "llvm/IR/Verifier.h"

#include <peToCFG.h>
#include <toLLVM.h>
#include <toModule.h>
#include <raiseX86.h>
#include "../common/to_string.h"
#include "../common/LExcn.h"
#include "../common/Defaults.h"

#include <boost/tokenizer.hpp>
#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>

using namespace llvm;
using namespace std;

static cl::opt<string>
OutputFilename("o", cl::desc("Output filename"), cl::init("-"),
               cl::value_desc("filename"));

static cl::opt<string>
InputFilename("i", cl::desc("Input filename"), cl::value_desc("<filename>"), cl::Required);

static cl::opt<string>
TargetTriple("mtriple", cl::desc("Target Triple"), cl::value_desc("target triple"), cl::init(DEFAULT_TRIPLE));

static cl::list<string>
Drivers("driver", 
        cl::desc("Describe externally visible entry points"), 
        cl::value_desc("<driver name>,<symbol | ep address>,<'raw' | argument count>,<'return' | 'noreturn'>,< calling convention: 'C', 'E', 'F'>"));

static cl::opt<bool>
OutputModule("m", cl::desc("Output native module format"));

static cl::opt<bool>
IgnoreUnsupported("ignore-unsupported", cl::desc("Ignore unsupported instructions"));

static cl::opt<bool>
EnablePostAnalysis("post-analysis", cl::desc("Enable post analysis and optimizations"), cl::init(true));

static cl::opt<bool>
ShouldVerify("should-verify", cl::desc("Verify module after bitcode emission?"), cl::init(true));

void printVersion(void) {
    cout << "0.6" << endl;
    return;
}

class block_label_writer {
private:
    NativeFunctionPtr func;
public:
    block_label_writer(NativeFunctionPtr f) : func(f) {
        return;
    }
    template <class VertexOrEdge>
    void operator()(ostream &out, const VertexOrEdge &v) const {
        NativeBlockPtr    curB = this->func->block_from_id(v);

        if( curB ) {
            string blockS = curB->print_block();
            out << "[label=\"" << blockS << "\"]";
        }

        return;
    }
};

void doPrintModule(NativeModulePtr m) {
    string  pathBase = "./";

    list<NativeFunctionPtr>           mod_funcs = m->get_funcs();
    list<NativeFunctionPtr>::iterator it = mod_funcs.begin();

    for(; it != mod_funcs.end(); ++it) {
        NativeFunctionPtr f = *it;
        string n =
            pathBase+to_string<uint64_t>(f->get_start(), hex) + ".dot";

        ofstream    out(n.c_str());

        block_label_writer  bgl(f);
        CFG                 g = f->get_cfg();
        write_graphviz(out, g, bgl);
    }

    return;
}


llvm::Module  *getLLVMModule(string name, const std::string &triple)
{
    llvm::Module  *M = new Module(name, llvm::getGlobalContext());
    llvm::Triple TT = llvm::Triple(triple);
    M->setTargetTriple(triple);
    

    std::string layout;

    if(TT.getOS() == llvm::Triple::Win32) {
        if(TT.getArch() == llvm::Triple::x86) {
            layout = "e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-f80:128:128-v64:64:64-v128:128:128-a0:0:64-f80:32:32-n8:16:32-S32";
        } else if(TT.getArch() == llvm::Triple::x86_64) {
            layout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128" ;
        } else {
            std::cerr << "Unsupported arch in triple: " << triple << "\n";
            return nullptr;
        }
    } else if (TT.getOS() == llvm::Triple::Linux) {
        if(TT.getArch() == llvm::Triple::x86) {
            layout = "e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:32:64-f32:32:32-f64:32:64-v64:64:64-v128:128:128-a0:0:64-f80:32:32-n8:16:32-S128";
        } else if(TT.getArch() == llvm::Triple::x86_64) {
            // x86_64-linux-gnu
            layout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128";
        } else {
            std::cerr << "Unsupported arch in triple: " << triple << "\n";
            return nullptr;
        }
    } else {
        std::cerr << "Unsupported OS in triple: " << triple << "\n";
        return nullptr;
    }

    M->setDataLayout(layout);

    doGlobalInit(M);

    return M;
}

struct DriverEntry 
{
    bool is_raw;
    bool returns;
    int  argc;
    string name;
    string sym;
	string sign;
    VA ep;
    ExternalCodeRef::CallingConvention cconv;
};

static VA string_to_int(const std::string &s) {
    VA ret;
    if(s.size() > 1 && (s[1] == 'x' || s[1] == 'X')) {
        ret = strtol(s.c_str(), NULL, 16);
    } else {
        ret = strtol(s.c_str(), NULL, 10);
    }

    // sanity check
    if( ret == 0 && s[0] != '0') {
        throw LErr(__LINE__, __FILE__, "Could not convert string to int: "+s);
    }

    return ret;
}

static bool driverArgsToDriver(const string &args, DriverEntry &new_d) {

    boost::char_separator<char> sep(",");
    boost::tokenizer<boost::char_separator<char> >  toks(args, sep);
    vector<string>  vtok;
    BOOST_FOREACH(const string &t, toks) { 
        vtok.push_back(t); 
    }

    if(vtok.size() >= 7) {
        return false;
    }

    // take name as is
    new_d.name = vtok[0];

    string sym_or_ep = vtok[1];
    char fl = sym_or_ep[0];
    // if the first letter is 0-9, assume its entry address
    if(fl >= '0' && fl <= '9') {
        new_d.sym = "";
        new_d.ep = string_to_int(sym_or_ep);
    } else {
    // if its not, assume entry symbol
        new_d.ep = 0;
        new_d.sym = sym_or_ep;
    }

    // check if this driver is raw
    boost::algorithm::to_lower(vtok[2]);
    if(vtok[2] == "raw") {
        new_d.is_raw = true;
    } else {
        // if not, parse number of arguments
        new_d.is_raw = false;
        new_d.argc = (int)string_to_int(vtok[2]);
    }

    // check if this "returns" or "noreturns"
    boost::algorithm::to_lower(vtok[3]);
    if(vtok[3] == "return") {
        new_d.returns = true;
    } else if (vtok[3] == "noreturn") {
        new_d.returns = false;
    } else {
        return false;
    }

    if(vtok[4] == "F") {
        new_d.cconv = ExternalCodeRef::FastCall;
    } else if(vtok[4] == "C") {
        new_d.cconv = ExternalCodeRef::CallerCleanup;
    } else if(vtok[4] == "E") {
        // default to stdcall
        new_d.cconv = ExternalCodeRef::CalleeCleanup;
    } else if(vtok[4] == "S") {
        // default to stdcall
        new_d.cconv = ExternalCodeRef::X86_64_SysV;
    } else if(vtok[4] == "W") {
		new_d.cconv = ExternalCodeRef::X86_64_Win64;
	}
	else {
        return false;
    }

	if(vtok.size() >= 6){
		 boost::algorithm::to_upper(vtok[5]);
		 new_d.sign = vtok[5];
	}

    return true;
}

static bool findSymInModule(NativeModulePtr mod, const std::string &sym, VA &ep) {
    const vector<NativeModule::EntrySymbol> &syms = mod->getEntryPoints();
    for(vector<NativeModule::EntrySymbol>::const_iterator itr = syms.begin();
        itr != syms.end();
        itr++ )
    {
        if(itr->getName() == sym) {
            ep = itr->getAddr();
            return true;
        }
    }

    ep = 0;
    return false;
}

// check if an entry point (to_find) is in the list of possible
// entry points for this module
static bool findEPInModule(NativeModulePtr mod, VA to_find, VA &ep) {
    const vector<NativeModule::EntrySymbol> &syms = mod->getEntryPoints();
    for(vector<NativeModule::EntrySymbol>::const_iterator itr = syms.begin();
        itr != syms.end();
        itr++ )
    {
        if(itr->getAddr() == to_find) {
            ep = to_find;
            return true;
        }
    }

    ep = 0;
    return false;
}

static bool haveDriverFor(const std::vector<DriverEntry> &drvs,
        const std::string &epname ) 
{
    for(std::vector<DriverEntry>::const_iterator it = drvs.begin();
            it != drvs.end();
            it++) 
    {
        // already have a driver for this entry point
        if (epname == it->sym) {
            cout << "Already have driver for: " << epname << std::endl;
            return true;
        }
    }

    return false;
}

int main(int argc, char *argv[]) 
{
  cl::SetVersionPrinter(printVersion);
  cl::ParseCommandLineOptions(argc, argv, "CFG to LLVM");

  InitializeAllTargetInfos();
  InitializeAllTargetMCs();
  InitializeAllAsmParsers();
  InitializeAllDisassemblers();

  if( InputFilename.size() == 0 || OutputFilename.size() == 0)
      return -1;

  vector<DriverEntry> drivers;

  std::string errstr;
  cout << "Looking up target..." << endl;
  const Target  *x86Target = 
      TargetRegistry::lookupTarget(TargetTriple, errstr);

  if(x86Target == nullptr) {
    std::cerr << "Could not find target triple: " << TargetTriple << "\n";
    std::cerr << "Error: " << errstr << "\n";
    return -1;
  }

  try {
      for(unsigned i = 0; i < Drivers.size(); i++) {
          string driverArgs = Drivers[i];
          DriverEntry d;
          if(!driverArgsToDriver(driverArgs, d)) {
              llvm::errs() << "Could not parse driver argument: " << driverArgs << "\n";
              return -1;
          }
          drivers.push_back(d);
      }
  } catch(std::exception &e) {
    cout << "error: " << endl << e.what() << endl;
    return -1;
  }

  //reproduce NativeModule from CFG input argument
  cout << "Reading module ..." << endl;
  NativeModulePtr mod = readModule(InputFilename, ProtoBuff, list<VA>(), x86Target);
  if(mod == NULL) {
      cerr << "Could not process input module: " << InputFilename << std::endl;
      return -2;
  }

  // set native module target
  cout << "Setting initial triples..." << endl;
  mod->setTarget(x86Target);
  mod->setTargetTriple(TargetTriple);

  const std::vector<NativeModule::EntrySymbol>& native_eps = mod->getEntryPoints();
  std::vector<NativeModule::EntrySymbol>::const_iterator natep_it;
  cout << "Looking at entry points..."  << endl;
  for( natep_it = native_eps.begin();
          natep_it != native_eps.end();
          natep_it++) 
  {
      const std::string &epname = natep_it->getName();
      if(! haveDriverFor(drivers, epname) && natep_it->hasExtra() ) {
            DriverEntry d;
            d.name = "driver_"+epname;
            d.sym = epname;
            d.ep = 0;
            d.argc = natep_it->getArgc();
            d.is_raw = false;
            d.returns = natep_it->doesReturn();
            d.cconv = natep_it->getConv();
            drivers.push_back(d);
            cout << "Automatically generating driver for: " << epname << std::endl;
      }
  }


  if(drivers.size() == 0) {
      cout << "At least one driver must be specified. Please use the -driver option\n";
      return -1;
  }

  if(!mod) {
    cout << "Unable to read module from CFG" << endl;
    return -1;
  }

  if(OutputModule)
    doPrintModule(mod);

  if(IgnoreUnsupported) {
      ignoreUnsupportedInsts = true;
  }

  //now, convert it to an LLVM module
  cout << "Getting LLVM module..."  << endl;
  llvm::Module  *M = getLLVMModule(mod->name(), TargetTriple);

  if(!M) 
  {
    cout << "Unable to get LLVM module" << endl;
    return -1;
  }

  bool  modResult = false;

  try {
    cout << "Converting to LLVM..."  << endl;
    modResult = natModToModule(mod, M, outs());
  } catch(std::exception &e) {
    cout << "error: " << endl << e.what() << endl;
    return -1;
  }

  if( modResult ) 
  {
      try {
          for(vector<DriverEntry>::const_iterator itr = drivers.begin();
                  itr != drivers.end();
                  itr++) 
          {

              VA ep = 0;

              // if this is a symbolic reference, look it up
              if(itr->ep == 0 && itr->sym != "") {
                  if(!findSymInModule(mod, itr->sym, ep)) {
                      llvm::errs() << "Could not find entry point: " << itr->sym << "; aborting\n";
                      return -1;
                  }

              } else {
                  // if this is an address reference, make sure its
                  // a valid entry point
                  if(!findEPInModule(mod, itr->ep, ep)) {
                      llvm::errs() << "Could not find entry address: " << 
                          to_string<VA>(itr->ep, hex) << "; aborting\n";
                      return -1;
                  }
              }

              cout << "Adding entry point: " << itr->name << std::endl;

              if(itr->is_raw == true)
              {
                  if(mod->is64Bit()) x86_64::addEntryPointDriverRaw(M, itr->name, ep);
                  else x86::addEntryPointDriverRaw(M, itr->name, ep);
              }
              else 
              {
                  if(mod->is64Bit()) {
                      x86_64::addEntryPointDriver(M, itr->name, ep, itr->argc, itr->returns, outs(), itr->cconv, itr->sign);
                  } else {
                      x86::addEntryPointDriver(M, itr->name, ep, itr->argc, itr->returns, outs(), itr->cconv);
                  }

              }

          } // for vector<DriverEntry>

          string                  errorInfo;
          llvm::tool_output_file  Out(OutputFilename.c_str(),
                  errorInfo,
                  sys::fs::F_None);

		  if(EnablePostAnalysis) {
              cout << "Doing post analysis passes...\n";
              doPostAnalysis(mod, M);
          } else {
              cout << "NOT doing post analysis passes.\n";
          }

          // will abort if verification fails
          if(ShouldVerify && llvm::verifyModule(*M, &errs())) {
              cerr << "Could not verify module!\n";
              return -1;
          }

          M->addModuleFlag(Module::Error, "Debug Info Version", DEBUG_METADATA_VERSION);
          M->addModuleFlag(Module::Error, "Dwarf Version", 3);

          WriteBitcodeToFile(M, Out.os());
          Out.keep(); 
      } catch(std::exception &e) {
          cout << "error: " << endl << e.what() << endl;
          return -1;
      }
  } 
  else 
  {
    cout << "Failure to convert to LLVM module!" << endl;
  }

  return 0;
}
