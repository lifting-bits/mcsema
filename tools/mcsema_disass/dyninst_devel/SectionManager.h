#pragma once

#include <Symtab.h>
#include <set>
#include <array>

class SectionManager {
public:
  void AddRegion(Dyninst::SymtabAPI::Region *r);

  bool IsData(Dyninst::Address a) const;
  bool IsCode(Dyninst::Address a) const;

  std::set<Dyninst::SymtabAPI::Region *> GetDataRegions() const;
  std::set<Dyninst::SymtabAPI::Region *> GetAllRegions() { return regions; }

  Dyninst::SymtabAPI::Region *getRodata() { return rodata; }
  Dyninst::SymtabAPI::Region *getText() { return text; }

  Dyninst::SymtabAPI::Region *getRegion(const std::string &name);

private:
  Dyninst::SymtabAPI::Region *text;
  Dyninst::SymtabAPI::Region *rodata;
  std::set<Dyninst::SymtabAPI::Region *> regions;

  std::array<std::string, 9> to_write_regions = {
    ".data",
    ".bss",
    ".plt",
    ".init",
    ".got.plt",
    ".eh_frame_hdr",
    ".rodata",
    ".fini",
    ".text"
  };
  std::set<Dyninst::SymtabAPI::Region *> data_regions;
};
