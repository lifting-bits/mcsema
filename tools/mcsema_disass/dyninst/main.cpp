/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "CFGWriter.h"
#include "ExternalFunctionManager.h"

#include <CodeObject.h>
#include <Dereference.h>
#include <Function.h>
#include <InstructionCategories.h>
#include <InstructionDecoder.h>
#include <Symtab.h>
#include <Variable.h>
#include <fstream>
#include <memory>

#include <CFG.h>
#include <map>
#include <sstream>

#include <glog/logging.h>
#include <gflags/gflags.h>

DEFINE_string(std_defs, "", "Path to file containing external definitions");
DEFINE_bool(dump_cfg, false, "Dump produced cfg on stdout");
DEFINE_bool(pretty_print, true, "Pretty printf the dumped cfg");
DEFINE_string(output, "", "Path to output file");
DEFINE_string(binary, "", "Path to binary to be disassembled");
DEFINE_string(entrypoint, "main", "Name of entrypoint function");
DEFINE_bool(pie_mode, false, "Need to be true for pie binaries");
DEFINE_string(arch, "", "NOT IMPLEMENTED YET");
DEFINE_string(os, "", "NOT IMPLEMENTED YET");

using namespace Dyninst;

const char kPathDelim = ',';

namespace {

static std::vector<std::string> Split(const std::string &s, const char delim) {
  std::vector<std::string> res;
  std::string rem;
  std::istringstream instream(s);

  while(std::getline(instream, rem, delim)) {
    res.push_back(rem);
  }

  return res;
}

}

/* There is a global context right now consisting of two groups
 * - gflags
 * - global object
 *    + gDisassContext -> Xref accounting and magic section
 *    + gSectionManager
 *    + gExtFuncManager
 *   this part can most likely be included in CFGWriter later on
 *
 * Parsing itself is managed by CFGWriter::Write(),
 * which is not reentrant!
 * Main itself is not reentrant, for multiple disasses multiple executions are
 * required (or reseting whole global context to initial values, not impl yet).
*/
int main(int argc, char **argv) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  std::stringstream ss;
  ss << "  " << argv[0] << "\\" << std::endl
     << "    --binary INPUT_FILE \\" << std::endl
     << "    --output OUTPUT CFG FILE \\" << std::endl
     << "    --std_defs FILE_NAME[" << kPathDelim <<
        "FILE_NAME,...] \\" << std::endl

     << "    [--pretty_print] \\" << std::endl
     << "    [--dump_cfg] \\" << std::endl;

  // Parse the command line arguments
  google::InitGoogleLogging(argv[0]);
  google::SetUsageMessage(ss.str());
  google::ParseCommandLineFlags(&argc, &argv, true);
  //FLAGS_logtostderr = 1;

  CHECK(!FLAGS_binary.empty()) << "Input file need to be specified";
  auto input_string = FLAGS_binary;
  auto input_file = const_cast<char *>(input_string.data());

  ExternalFunctionManager extFuncManager;
  // Load external symbol definitions
  if (!FLAGS_std_defs.empty()) {
    auto std_defs = Split(FLAGS_std_defs, kPathDelim);
    for (const auto &filename : std_defs) {
      LOG(INFO) << "Loading file containing external definitions";
      auto file = std::ifstream{filename};
      extFuncManager.AddExternalSymbols(file);
    }
  }

  // Set up Dyninst stuff
  auto symtab_cs =
      std::make_shared<ParseAPI::SymtabCodeSource>(input_file);
  CHECK(symtab_cs) << "Error during creation of ParseAPI::SymtabCodeSource!";

  auto code_object = std::make_shared<ParseAPI::CodeObject>(symtab_cs.get());
  CHECK(code_object) << "Error during creation of ParseAPI::CodeObject";

  code_object->parse();

  // If binary is stripped we need to try some speculative parsing
  // We try both options that DynInst provides
  auto idiom = Dyninst::ParseAPI::GapParsingType::PreambleMatching;
  for (auto &reg : symtab_cs->regions()) {
    code_object->parseGaps(reg, idiom);
    code_object->parseGaps(reg);
  }

  auto symtab = symtab_cs->getSymtabObject();
  CHECK(symtab) << "Error during creation of SymtabObject";

  // Mark the functions that appear in the module as used (so that
  // they will be listed as external symbols in the CFG file)

  for (auto p : code_object->cs()->linkage()) {
    std::vector<SymtabAPI::Function *> fs;

    // Only mark external functions
    if (!(symtab->findFunctionsByName(fs, p.second)))
      extFuncManager.MarkAsUsed(p.second);
  }

  if (FLAGS_output.empty()) {
    LOG(ERROR) << "No output file provided, output is not written into file!";
  }
  std::ofstream out{FLAGS_output};
  if (!out) {
    LOG(FATAL) << "Problem while opening output file";
  }

  mcsema::Module m;

  CFGWriter(m, *symtab, *code_object, extFuncManager).Write();

  // Dump the CFG file in a human-readable format if requested
  if (FLAGS_dump_cfg) {
    std::cout << std::hex << m.DebugString() << std::endl;
  }

  m.SerializeToOstream(&out);

  google::protobuf::ShutdownProtobufLibrary();

  return 0;
}
