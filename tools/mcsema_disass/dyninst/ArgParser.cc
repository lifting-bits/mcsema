#include "ArgParser.hpp"
#include <cstdlib>
#include <iostream>

ArgParser::ArgParser (int argc, char **argv)
    : m_appName (argv [0]), m_args (),
      m_inputFiles (), m_stdDefFiles (),
      m_dumpCfg (false), m_prettyPrintCfg (false),
      m_outputFiles (), m_addExtSyms ()
{
    for (int i = 1; i < argc; ++i)
        m_args.push_back ({ argv [i] });

    if (m_args.size () == 1)
    {
        if ((m_args.front () == "--help" ) || (m_args.back () == "-h"))
        {
            printHelp ();
            std::exit (0);
        }
    }

    while (!m_args.empty ())
    {
        auto curArg = m_args.front ();

        if (curArg.front () == '-')
        {
            if ((curArg == "-h") || (curArg == "--help"))
                throw std::runtime_error { "-h and --help may not be used in conjunction with other arguments" };
            else if (curArg == "--std-defs")
            {
                m_args.pop_front ();

                if (m_args.empty ())
                    throw std::runtime_error { "--std-defs option needs an argument" };

                m_stdDefFiles.push_back (m_args.front ());
            }
            else if (curArg == "--dump-cfg")
            {
                m_dumpCfg = true;
            }
            else if (curArg == "--pretty-print")
            {
                m_prettyPrintCfg = true;
            }
            else if (curArg == "--no-pretty-print")
            {
                m_prettyPrintCfg = false;
            }
            else if (curArg == "-o")
            {
                m_args.pop_front ();

                if (m_args.empty ())
                    throw std::runtime_error { "-o option needs an argument" };

                m_outputFiles.push_back (m_args.front ());
            }
            else if (curArg == "--add-ext-sym")
            {
                m_args.pop_front ();

                if (m_args.empty ())
                    throw std::runtime_error { "--add-ext-sym option needs an argument" };

                m_addExtSyms.push_back (m_args.front ());
            }
            else
            {
                std::cerr << "unrecognized command line option: \"" << curArg << "\"" << std::endl;
                std::cerr << "use `" << m_appName << " --help` for a list of available options" << std::endl;
                throw std::runtime_error { "unrecognized command line option" };
            }
        }
        else
            m_inputFiles.push_back (curArg);

        m_args.pop_front ();
    }
}

void ArgParser::printHelp () const
{
    std::cout
        << "Available options:" << std::endl
        << std::endl
        << "  -h, --help: prints this help text" << std::endl
        << "  --std-defs <FILE>: read external symbol definitions from <FILE>" << std::endl
        << "                     (may be used multiple times)" << std::endl
        << "  --dump-cfg: print the created CFG file to stdout in a human-readable format" << std::endl
        << "  --[no-]pretty-print: pretty-print the CFG file (default: on)" << std::endl
        << "                       (only makes sense with --dump-cfg)" << std::endl
        << "  -o <FILE>: output resulting CFG into <FILE> (default: none)" << std::endl
        << "  --add-ext-sym <DESCRIPTION>: parse <DESCRIPTION> as if it were a line in a" << std::endl
        << "                               symbol definitions file" << std::endl
        ;
}

const std::string& ArgParser::getAppName () const
{
    return m_appName;
}

const std::vector<std::string>& ArgParser::getInputFiles () const
{
    return m_inputFiles;
}

const std::vector<std::string>& ArgParser::getStdDefFiles () const
{
    return m_stdDefFiles;
}

const bool ArgParser::getDumpCfg () const
{
    return m_dumpCfg;
}

const bool ArgParser::getPrettyPrintCfg () const
{
    return m_prettyPrintCfg;
}

const std::vector<std::string>& ArgParser::getOutputFiles () const
{
    return m_outputFiles;
}

const std::vector<std::string>& ArgParser::getAddExtSyms () const
{
    return m_addExtSyms;
}
