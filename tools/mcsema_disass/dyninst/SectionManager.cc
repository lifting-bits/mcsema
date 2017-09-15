#include "SectionManager.hpp"

using namespace Dyninst;
using namespace SymtabAPI;

void SectionManager::addRegion (Region *r)
{
    if (m_regions.find (r) == m_regions.end ())
        m_regions.insert (r);
}

bool SectionManager::isData (Address a) const
{
    auto dataRegions { getDataRegions () };
    const Offset o = (const Offset) a;

    for (auto r : dataRegions)
    {
        if (r->isOffsetInRegion (o))
            return true;
    }

    return false;
}

bool SectionManager::isCode (Address a) const
{
    return !isData (a);
}

std::set<Region *> SectionManager::getDataRegions () const
{
    std::set<Region *> result;

    for (Region *r : m_regions)
    {
        if (!r->isText ())
            result.insert (r);
    }

    return result;
}
