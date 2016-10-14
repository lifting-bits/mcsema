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

static cl::opt<string> OutputFilename("o", cl::desc("Output filename"),
                                      cl::init("-"),
                                      cl::value_desc("filename"));

static cl::opt<string> InputFilename("i", cl::desc("Input filename"),
                                     cl::value_desc("<filename>"),
                                     cl::Required);

static cl::opt<string> TargetTriple("mtriple", cl::desc("Target Triple"),
                                    cl::value_desc("target triple"),
                                    cl::init(DEFAULT_TRIPLE));

static cl::list<string> EntryPoints(
    "entrypoint", cl::desc("Describe externally visible entry points"),
    cl::value_desc("<symbol | ep address>"));

static cl::opt<bool> OutputModule("m", cl::desc("Output native module format"));

static cl::opt<bool> IgnoreUnsupported(
    "ignore-unsupported", cl::desc("Ignore unsupported instructions"));

static cl::opt<bool> EnablePostAnalysis(
    "post-analysis", cl::desc("Enable post analysis and optimizations"),
    cl::init(true));

static cl::opt<bool> ShouldVerify(
    "should-verify", cl::desc("Verify module after bitcode emission?"),
    cl::init(true));

void printVersion(void) {
  cout << "0.6" << endl;
  return;
}

class block_label_writer {
 private:
  NativeFunctionPtr func;
 public:
  block_label_writer(NativeFunctionPtr f)
      : func(f) {
    return;
  }
  template<class VertexOrEdge>
  void operator()(ostream &out, const VertexOrEdge &v) const {
    NativeBlockPtr curB = this->func->block_from_id(v);

    if (curB) {
      string blockS = curB->print_block();
      out << "[label=\"" << blockS << "\"]";
    }

    return;
  }
};

void doPrintModule(NativeModulePtr m) {
  string pathBase = "./";

  list<NativeFunctionPtr> mod_funcs = m->get_funcs();
  list<NativeFunctionPtr>::iterator it = mod_funcs.begin();

  for (; it != mod_funcs.end(); ++it) {
    NativeFunctionPtr f = *it;
    string n = pathBase + to_string<uint64_t>(f->get_start(), hex) + ".dot";

    ofstream out(n.c_str());

    block_label_writer bgl(f);
    CFG g = f->get_cfg();
    write_graphviz(out, g, bgl);
  }

  return;
}

llvm::Module *getLLVMModule(string name, const std::string &triple) {
  llvm::Module *M = new Module(name, llvm::getGlobalContext());
  llvm::Triple TT = llvm::Triple(triple);
  M->setTargetTriple(triple);

  std::string layout;

  if (TT.getOS() == llvm::Triple::Win32) {
    if (TT.getArch() == llvm::Triple::x86) {
      layout =
          "e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-f80:128:128-v64:64:64-v128:128:128-a0:0:64-f80:32:32-n8:16:32-S32";
    } else if (TT.getArch() == llvm::Triple::x86_64) {
      layout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128";
    } else {
      std::cerr << "Unsupported arch in triple: " << triple << "\n";
      return nullptr;
    }
  } else if (TT.getOS() == llvm::Triple::Linux) {
    if (TT.getArch() == llvm::Triple::x86) {
      layout =
          "e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:32:64-f32:32:32-f64:32:64-v64:64:64-v128:128:128-a0:0:64-f80:32:32-n8:16:32-S128";
    } else if (TT.getArch() == llvm::Triple::x86_64) {
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

struct DriverEntry {
  bool is_raw;
  bool returns;
  int argc;
  string name;
  string sym;
  string sign;
  VA ep;
  ExternalCodeRef::CallingConvention cconv;
};

static VA string_to_int(const std::string &s) {
  VA ret;
  if (s.size() > 1 && (s[1] == 'x' || s[1] == 'X')) {
    ret = strtol(s.c_str(), NULL, 16);
  } else {
    ret = strtol(s.c_str(), NULL, 10);
  }

  // sanity check
  if (ret == 0 && s[0] != '0') {
    throw LErr(__LINE__, __FILE__, "Could not convert string to int: " + s);
  }

  return ret;
}

static bool driverArgsToDriver(const string &args, DriverEntry &new_d) {

  boost::char_separator<char> sep(",");
  boost::tokenizer<boost::char_separator<char> > toks(args, sep);
  vector<string> vtok;
  BOOST_FOREACH(const string &t, toks){
  vtok.push_back(t);
}

  if (vtok.size() >= 7) {
    return false;
  }

  // take name as is
  new_d.name = vtok[0];

  string sym_or_ep = vtok[1];
  char fl = sym_or_ep[0];
  // if the first letter is 0-9, assume its entry address
  if (fl >= '0' && fl <= '9') {
    new_d.sym = "";
    new_d.ep = string_to_int(sym_or_ep);
  } else {
    // if its not, assume entry symbol
    new_d.ep = 0;
    new_d.sym = sym_or_ep;
  }

  // check if this driver is raw
  boost::algorithm::to_lower(vtok[2]);
  if (vtok[2] == "raw") {
    new_d.is_raw = true;
  } else {
    // if not, parse number of arguments
    new_d.is_raw = false;
    new_d.argc = (int) string_to_int(vtok[2]);
  }

  // check if this "returns" or "noreturns"
  boost::algorithm::to_lower(vtok[3]);
  if (vtok[3] == "return") {
    new_d.returns = true;
  } else if (vtok[3] == "noreturn") {
    new_d.returns = false;
  } else {
    return false;
  }

  if (vtok[4] == "F") {
    new_d.cconv = ExternalCodeRef::FastCall;
  } else if (vtok[4] == "C") {
    new_d.cconv = ExternalCodeRef::CallerCleanup;
  } else if (vtok[4] == "E") {
    // default to stdcall
    new_d.cconv = ExternalCodeRef::CalleeCleanup;
  } else if (vtok[4] == "S") {
    // default to stdcall
    new_d.cconv = ExternalCodeRef::X86_64_SysV;
  } else if (vtok[4] == "W") {
    new_d.cconv = ExternalCodeRef::X86_64_Win64;
  } else {
    return false;
  }

  if (vtok.size() >= 6) {
    boost::algorithm::to_upper(vtok[5]);
    new_d.sign = vtok[5];
  }

  return true;
}

static bool findSymInModule(NativeModulePtr mod, const std::string &sym,
                            VA &ep) {
  const vector<NativeModule::EntrySymbol> &syms = mod->getEntryPoints();
  for (vector<NativeModule::EntrySymbol>::const_iterator itr = syms.begin();
      itr != syms.end(); itr++) {
    if (itr->getName() == sym) {
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
  for (vector<NativeModule::EntrySymbol>::const_iterator itr = syms.begin();
      itr != syms.end(); itr++) {
    if (itr->getAddr() == to_find) {
      ep = to_find;
      return true;
    }
  }

  ep = 0;
  return false;
}

static bool haveDriverFor(const std::vector<DriverEntry> &drvs,
                          const std::string &epname) {
  for (std::vector<DriverEntry>::const_iterator it = drvs.begin();
      it != drvs.end(); it++) {
    // already have a driver for this entry point
    if (epname == it->sym) {
      cout << "Already have driver for: " << epname << std::endl;
      return true;
    }
  }

  return false;
}

int main(int argc, char *argv[]) {
  cl::SetVersionPrinter(printVersion);
  cl::ParseCommandLineOptions(argc, argv, "CFG to LLVM");

  InitializeAllTargetInfos();
  InitializeAllTargetMCs();
  InitializeAllAsmParsers();
  InitializeAllDisassemblers();

  if (InputFilename.empty() || OutputFilename.empty()) {
    std::cerr << "Must specify an input and output file";
    return EXIT_FAILURE;
  }

  std::string errstr;
  std::cerr << "Looking up target..." << endl;
  const Target *x86Target = TargetRegistry::lookupTarget(TargetTriple, errstr);

  if (x86Target == nullptr) {
    std::cerr << "Could not find target triple: " << TargetTriple << std::endl
              << "Error: " << errstr << "\n";
    return EXIT_FAILURE;
  }

  //reproduce NativeModule from CFG input argument
  std::cerr << "Reading module ..." << endl;
  NativeModulePtr mod = readModule(InputFilename, ProtoBuff, list<VA>(),
                                   x86Target);
  if (mod == NULL) {
    std::cerr << "Could not process input module: " << InputFilename
              << std::endl;
    return EXIT_FAILURE;
  }

  // set native module target
  std::cerr << "Setting initial triples..." << endl;
  mod->setTarget(x86Target);
  mod->setTargetTriple(TargetTriple);

  if ( !mod) {
    std::cerr << "Unable to read module from CFG" << endl;
    return EXIT_FAILURE;
  }

  if (OutputModule) {
    doPrintModule(mod);
  }

  if (IgnoreUnsupported) {
    ignoreUnsupportedInsts = true;
  }

  //now, convert it to an LLVM module
  std::cerr << "Getting LLVM module..." << endl;
  llvm::Module *M = getLLVMModule(mod->name(), TargetTriple);

  if (!M) {
    std::cerr << "Unable to get LLVM module" << endl;
    return EXIT_FAILURE;
  }

  try {
    initAttachDetach(M);

    std::cerr << "Converting to LLVM..." << endl;
    if ( !natModToModule(mod, M, outs())) {
      std::cerr << "Failure to convert to LLVM module!" << endl;
      return EXIT_FAILURE;
    }

    for (const auto &entry_point_name : EntryPoints) {
      VA ep = 0;
      std::cerr << "Adding entry point: " << entry_point_name << std::endl;
      if (findSymInModule(mod, entry_point_name, ep)) {
        std::cerr << entry_point_name << " is implemented by sub_" << std::hex << ep << std::endl;
        if (!addEntryPointDriver(M, entry_point_name, ep)) {
          return EXIT_FAILURE;
        }

      } else {
        llvm::errs() << "Could not find entry point: " << entry_point_name
                     << "; aborting\n";
        return EXIT_FAILURE;
      }
    }

    string errorInfo;
    llvm::tool_output_file Out(OutputFilename.c_str(), errorInfo,
                               sys::fs::F_None);

    if (EnablePostAnalysis) {
      std::cerr << "Doing post analysis passes...\n";
      doPostAnalysis(mod, M);
    } else {
      std::cerr << "NOT doing post analysis passes.\n";
    }

    // will abort if verification fails
    if (ShouldVerify && llvm::verifyModule( *M, &errs())) {
      std::cerr << "Could not verify module!\n";
      return EXIT_FAILURE;
    }

    M->addModuleFlag(Module::Error, "Debug Info Version",
                     DEBUG_METADATA_VERSION);
    M->addModuleFlag(Module::Error, "Dwarf Version", 3);

    WriteBitcodeToFile(M, Out.os());
    Out.keep();
  } catch (std::exception &e) {
    std::cerr << "error: " << endl << e.what() << endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
