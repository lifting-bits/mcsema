#ifndef PETARGET_H
#define PETARGET_H

#include <vector>
#include <string>
#include <list>
#include <utility>
#include "bincomm.h"
//PE file headers
#include "pe-parse/parser-library/parse.h"

class PeTarget : public ExecutableContainer {
  parsed_pe *pe;
  std::string    mod_name;
public:
  PeTarget(std::string f, const llvm::Target *T);
  virtual ~PeTarget(void);
  virtual bool is_open(void);
  virtual bool find_import_name(uint32_t, std::string &);
  virtual bool get_exports(std::list<std::pair<std::string, VA> >  &);
  virtual bool is_addr_relocated(uint32_t);
  virtual bool relocate_addr(VA, VA&);
  virtual bool get_sections(std::vector<SectionDesc>  &);
  virtual std::string name(void) { return this->mod_name; }
  virtual ::uint64_t getBase(void) const;
  virtual ::uint64_t getExtent(void) const;
  virtual int readByte(::uint64_t, uint8_t *) const;
};

#endif
