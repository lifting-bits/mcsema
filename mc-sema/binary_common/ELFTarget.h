#ifndef ELFTARGET_H
#define ELFTARGET_H

#include <string>
#include "LLVMObjectTarget.h"


class ElfTarget : public LLVMObjectTarget {
public:
    static ElfTarget* CreateElfTarget(std::string f, const llvm::Target *T);
    virtual ~ElfTarget(void) {};
private:
    ElfTarget();
protected:
  ElfTarget(const std::string &modname, llvm::object::ObjectFile *of): LLVMObjectTarget(modname, of) {};
}; 

#endif
