#pragma once

#include <istream>
#include <map>
#include <set>
#include <string>
#include "ExternalFunc.hpp"

class ExternalFunctionManager
{
public:
    /* The following methods can be used to register external
     * functions with the ExternalFunctionManager. If the same name is
     * used multiple times, the information will be overwritten.
     */

    // Registers a function called "name" with info "func"
    void addExternalSymbol (const std::string& name, const ExternalFunc& func);

    // Parses s as if it were a line in a function definitions file
    void addExternalSymbol (const std::string& s);

    // Reads from s as if it were a function definitions file
    void addExternalSymbols (std::istream& s);

    // Un-mark a function as external
    void removeExternalSymbol (const std::string& name);


    // Returns true iff the function called "name" is external
    bool isExternal (const std::string& name) const;

    // Returns the information stored for the function called "name"
    // and throws an exception if no such function can be found.
    const ExternalFunc& getExternalFunction (const std::string& name) const;

    /* The following methods can be used to keep track of the external
     * functions that are actually called somewhere. This can greatly
     * reduce the external_funcs blocks in the CFG file.
     */
    void clearUsed ();
    void markAsUsed (const std::string& name);
    std::set<ExternalFunc> getAllUsed () const;

private:
    std::map<std::string,ExternalFunc> m_extFuncs;
    std::set<std::string> m_usedFuncs;
};
