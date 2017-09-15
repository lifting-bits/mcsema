#pragma once

#include <string>
#include <deque>
#include <vector>

class ArgParser
{
public:
    ArgParser () = delete;
    ArgParser (int argc, char **argv);

    void printHelp () const;

    const std::string& getAppName () const;
    const std::vector<std::string>& getInputFiles () const;
    const std::vector<std::string>& getStdDefFiles () const;
    const bool getDumpCfg () const;
    const bool getPrettyPrintCfg () const;
    const std::vector<std::string>& getOutputFiles () const;
    const std::vector<std::string>& getAddExtSyms () const;

private:
    std::string m_appName;
    std::deque<std::string> m_args;

    std::vector<std::string> m_inputFiles;
    std::vector<std::string> m_stdDefFiles;
    bool m_dumpCfg;
    bool m_prettyPrintCfg;
    std::vector<std::string> m_outputFiles;
    std::vector<std::string> m_addExtSyms;
};
