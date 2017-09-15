#include <iostream>
#include <fstream>
#include <memory>
#include <CodeObject.h>
#include <InstructionDecoder.h>
#include <Symtab.h>
#include <Variable.h>
#include <Dereference.h>
#include <Function.h>
#include <InstructionCategories.h>
#include "SectionManager.hpp"
#include "ArgParser.hpp"
#include "ExternalFunctionManager.hpp"
#include "CFGWriter.hpp"

using namespace Dyninst;

int main (int argc, char **argv)
{
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    // Parse the command line arguments

    ArgParser argParser (argc, argv);

    // We need exactly one input file

    if (argParser.getInputFiles ().size () < 1)
        throw std::runtime_error { "need exactly one input file" };
    else if (argParser.getInputFiles ().size () > 1)
        throw std::runtime_error { "more than one input file specified" };

    auto inputFile = argParser.getInputFiles ().front ();

    // Load external symbol definitions (for now, only functions)

    ExternalFunctionManager extFuncMgr;

    for (auto stdDefFile : argParser.getStdDefFiles ())
    {
        std::ifstream file (stdDefFile);
        extFuncMgr.addExternalSymbols (file);
    }

    for (const auto& extSymDef : argParser.getAddExtSyms ())
        extFuncMgr.addExternalSymbol (extSymDef);

    extFuncMgr.clearUsed ();

    // Set up Dyninst stuff

    auto symtabCS = std::make_shared<ParseAPI::SymtabCodeSource> ((char *) inputFile.c_str ());
    if (!symtabCS)
        return 1;

    auto symtab = symtabCS->getSymtabObject ();
    if (!symtab)
        return 1;

    auto codeObj = std::make_shared<ParseAPI::CodeObject> (symtabCS.get ());
    if (!codeObj)
        return 1;

    codeObj->parse ();

    // Mark the functions that appear in the module as used (so that
    // they will be listed as external symbols in the CFG file)

    for (auto p : codeObj->cs ()->linkage ())
    {
        std::vector<SymtabAPI::Function *> fs;

        // Only mark external functions
        if (!(symtab->findFunctionsByName (fs, p.second)))
            extFuncMgr.markAsUsed (p.second);
    }

    // This is the main Protobuf object we will write into

    mcsema::Module m;

    // Write the CFG information to m

    CFGWriter cfgWriter (m, inputFile, *symtab, *codeObj, extFuncMgr);
    cfgWriter.write ();

    // Dump the CFG file in a human-readable format if requested

    if (argParser.getDumpCfg () == true)
    {
        if (argParser.getPrettyPrintCfg () == false)
            std::cout << m.DebugString () << std::endl;
        else
            throw std::runtime_error { "pretty-printing the new format is not yet supported" };
    }

    // Output CFG file

    std::string outputFile;

    if (argParser.getOutputFiles ().size () == 1)
    {
        auto outputFile = argParser.getOutputFiles ().front ();
        std::ofstream out (outputFile.c_str ());
        m.SerializeToOstream (&out);
    }
    else if (argParser.getOutputFiles ().size () > 1)
        throw std::runtime_error { "multiple output files specified" };
    /* The else block is omitted intentionally. The user might not
     * want the CFG file, maybe because he only wants to see the
     * human-readable format and is not interested in the CFG file.
     * However, we do issue a warning if no output is generated at
     * all.
     */
    else if ((argParser.getOutputFiles ().size () < 1)
             && (argParser.getDumpCfg () == false))
        std::cerr << "warning: no output generated" << std::endl;

    google::protobuf::ShutdownProtobufLibrary();

    return 0;
}
