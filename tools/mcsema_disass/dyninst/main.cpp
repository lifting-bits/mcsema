#include "CFGWriter.h"
#include "ExternalFunctionManager.h"
#include "SectionManager.h"

#include <CodeObject.h>
#include <Dereference.h>
#include <Function.h>
#include <InstructionCategories.h>
#include <InstructionDecoder.h>
#include <Symtab.h>
#include <Variable.h>
#include <fstream>
#include <iostream>
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
  auto inputFile = FLAGS_binary;

  // Load external symbol definitions (for now, only functions)
  ExternalFunctionManager extFuncMgr;

  if (!FLAGS_std_defs.empty()) {
    auto std_defs = Split(FLAGS_std_defs, kPathDelim);
    for (const auto &file_name : std_defs) {
      LOG(INFO) << "Loading file containing external definitions";
      auto file = std::ifstream{file_name};
      extFuncMgr.addExternalSymbols(file);
    }
  }

  //TODO(lukas): Check how it is parsed
  /*
  for (const auto &extSymDef : argParser.getAddExtSyms())
    extFuncMgr.addExternalSymbol(extSymDef);
  */
  extFuncMgr.clearUsed();

  // Set up Dyninst stuff

  auto symtabCS =
      std::make_shared<ParseAPI::SymtabCodeSource>((char *)inputFile.c_str());
  if (!symtabCS)
    return 1;

  auto symtab = symtabCS->getSymtabObject();
  if (!symtab)
    return 1;

  auto codeObj = std::make_shared<ParseAPI::CodeObject>(symtabCS.get());
  if (!codeObj)
    return 1;

  codeObj->parse();

  // Mark the functions that appear in the module as used (so that
  // they will be listed as external symbols in the CFG file)

  for (auto p : codeObj->cs()->linkage()) {
    std::vector<SymtabAPI::Function *> fs;

    // Only mark external functions
    if (!(symtab->findFunctionsByName(fs, p.second)))
      extFuncMgr.markAsUsed(p.second);
  }

  if (FLAGS_output.empty()) {
    LOG(ERROR) << "No output file provided, output is not written into file!";
  }
  std::ofstream out{FLAGS_output};
  if (!out) {
    LOG(FATAL) << "Problem while opening output file";
  }


  mcsema::Module m;

  CFGWriter cfgWriter(m, inputFile, *symtab, *symtabCS, *codeObj, extFuncMgr);
  cfgWriter.write();

  // Dump the CFG file in a human-readable format if requested
  if (FLAGS_dump_cfg) {
      std::cout << std::hex << m.DebugString() << std::endl;
  }

  m.SerializeToOstream(&out);

  google::protobuf::ShutdownProtobufLibrary();

  return 0;
}
