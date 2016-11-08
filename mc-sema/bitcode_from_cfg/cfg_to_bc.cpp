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

#include <iostream>
#include <string>
#include <sstream>

#include "llvm/ADT/Triple.h"
#include "llvm/ADT/Twine.h"

#include "llvm/Bitcode/ReaderWriter.h"

#include "llvm/IR/Verifier.h"
#include "llvm/IR/LLVMContext.h"

#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCSubtargetInfo.h"

#include "llvm/Object/COFF.h"

#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/MemoryObject.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/TargetSelect.h"

#include <peToCFG.h>
#include <toLLVM.h>
#include <toModule.h>
#include <raiseX86.h>
#include <InstructionDispatch.h>

#include "../common/to_string.h"
#include "../common/LExcn.h"
#include "../common/Defaults.h"

#include <boost/tokenizer.hpp>
#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>

using namespace llvm;

static cl::opt<std::string> OutputFilename("o", cl::desc("Output filename"),
                                           cl::init("-"),
                                           cl::value_desc("filename"));

static cl::opt<std::string> InputFilename("i", cl::desc("Input filename"),
                                          cl::value_desc("<filename>"),
                                          cl::Required);

static cl::opt<std::string> TargetTriple("mtriple", cl::desc("Target Triple"),
                                         cl::value_desc("target triple"),
                                         cl::init(DEFAULT_TRIPLE));

static cl::list<std::string> EntryPoints(
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

static void printVersion(void) {
  std::cout << "0.6" << std::endl;
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
  void operator()(std::ostream &out, const VertexOrEdge &v) const {
    NativeBlockPtr curB = this->func->block_from_id(v);

    if (curB) {
      std::string blockS = curB->print_block();
      out << "[label=\"" << blockS << "\"]";
    }

    return;
  }
};

static void doPrintModule(NativeModulePtr m) {
  std::string pathBase = "./";

  for (auto f : m->get_funcs()) {
    std::string n = pathBase + to_string<uint64_t>(f->get_start(), std::hex)
        + ".dot";

    std::ofstream out(n.c_str());

    block_label_writer bgl(f);
    CFG g = f->get_cfg();
    write_graphviz(out, g, bgl);
  }

  return;
}

llvm::Module *createModuleForArch(std::string name, const std::string &triple) {
  llvm::Module *M = new llvm::Module(name, llvm::getGlobalContext());
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
  return M;
}

static VA findSymInModule(NativeModulePtr mod, const std::string &sym_name) {
  for (auto &sym : mod->getEntryPoints()) {
    if (sym.getName() == sym_name) {
      return sym.getAddr();
    }
  }
  return (VA)(-1);
}

int main(int argc, char *argv[]) {
  llvm::cl::SetVersionPrinter(printVersion);
  llvm::cl::ParseCommandLineOptions(argc, argv, "CFG to LLVM");

  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

  if (InputFilename.empty() || OutputFilename.empty()) {
    std::cerr << "Must specify an input and output file";
    return EXIT_FAILURE;
  }

  std::string errstr;
  std::cerr << "Looking up target..." << std::endl;
  auto x86Target = llvm::TargetRegistry::lookupTarget(TargetTriple, errstr);

  if (!x86Target) {
    std::cerr
      << "Could not find target triple: " << TargetTriple << std::endl
      << "Error: " << errstr << "\n";
    return EXIT_FAILURE;
  }

  //reproduce NativeModule from CFG input argument
  std::cerr << "Reading module ..." << std::endl;
  try {
    auto mod = readModule(InputFilename, ProtoBuff, std::list<VA>(), x86Target);
    if (!mod) {
      std::cerr << "Could not process input module: " << InputFilename
          << std::endl;
      return EXIT_FAILURE;
    }

    // set native module target
    std::cerr << "Setting initial triples..." << std::endl;
    mod->setTarget(x86Target);
    mod->setTargetTriple(TargetTriple);

    if ( !mod) {
      std::cerr << "Unable to read module from CFG" << std::endl;
      return EXIT_FAILURE;
    }

    if (OutputModule) {
      doPrintModule(mod);
    }

    if (IgnoreUnsupported) {
      ignoreUnsupportedInsts = true;
    }

    //now, convert it to an LLVM module
    std::cerr << "Getting LLVM module..." << std::endl;
    auto M = createModuleForArch(mod->name(), TargetTriple);

    if ( !M) {
      std::cerr << "Unable to get LLVM module" << std::endl;
      return EXIT_FAILURE;
    }

    initRegStateStruct(M);
    ArchInitAttachDetach(M);
    initInstructionDispatch();

    std::cerr << "Converting to LLVM..." << std::endl;
    if (!liftNativeCodeIntoModule(mod, M)) {
      std::cerr << "Failure to convert to LLVM module!" << std::endl;
      return EXIT_FAILURE;
    }

    std::set<VA> entry_point_pcs;

    for (const auto &entry_point_name : EntryPoints) {
      std::cerr << "Adding entry point: " << entry_point_name << std::endl;

      auto entry_pc = findSymInModule(mod, entry_point_name);
      if ((VA)(-1) != entry_pc) {
        std::cerr << entry_point_name << " is implemented by sub_" << std::hex
                  << entry_pc << std::endl;

        if (!ArchAddEntryPointDriver(M, entry_point_name, entry_pc)) {
          return EXIT_FAILURE;
        }

        entry_point_pcs.insert(entry_pc);
      } else {
        llvm::errs() << "Could not find entry point: " << entry_point_name
                     << "; aborting\n";
        return EXIT_FAILURE;
      }
    }

    renameLiftedFunctions(mod, M, entry_point_pcs);

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

    std::string errorInfo;
    llvm::tool_output_file Out(OutputFilename.c_str(), errorInfo,
                               sys::fs::F_None);
    WriteBitcodeToFile(M, Out.os());
    Out.keep();
  } catch (std::exception &e) {
    std::cerr << "error: " << std::endl << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
