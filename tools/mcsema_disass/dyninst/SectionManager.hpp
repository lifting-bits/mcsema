#pragma once

#include <Symtab.h>
#include <set>

class SectionManager
{
public:
    void addRegion (Dyninst::SymtabAPI::Region *r);

    bool isData (Dyninst::Address a) const;
    bool isCode (Dyninst::Address a) const;

    std::set<Dyninst::SymtabAPI::Region *> getDataRegions () const;

private:
    std::set<Dyninst::SymtabAPI::Region *> m_regions;
};
