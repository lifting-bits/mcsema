#ifndef LLVMOBJECTTARGET_H
#define LLVMOBJECTTARGET_H

#include <vector>
#include <string>
#include <list>

#include "bincomm.h"

class LLVMObjectTarget : public ExecutableContainer {
  std::string                    mod_name;
  //(a, b) -- a is offset to apply to base of secT to get its real base
  //len remainds the same

  llvm::object::ObjectFile    *objectfile;
  VA                        baseAddr;
  VA                        extent;
public:
  typedef std::pair<boost::uint64_t, llvm::object::SectionRef>  secT;

  virtual ~LLVMObjectTarget(void);
  virtual bool is_open(void);
  virtual bool get_exports(std::list<std::pair<std::string, VA> > &);
  virtual bool find_import_name(uint32_t, std::string &);
  virtual bool is_addr_relocated(uint32_t);
  virtual bool relocate_addr(VA, VA &);
  virtual bool get_sections(std::vector<SectionDesc>  &);
  virtual std::string name(void) { return this->mod_name; }
  virtual ::uint64_t getBase(void) const;
  virtual ::uint64_t getExtent(void) const;
  virtual int readByte(::uint64_t, uint8_t *) const;
protected:
  std::vector<secT>              secs;

  LLVMObjectTarget(const std::string &modname, llvm::object::ObjectFile *of);

private:
    LLVMObjectTarget();

};

#endif
