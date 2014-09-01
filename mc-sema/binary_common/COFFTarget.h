#ifndef COFFTARGET_H
#define COFFTARGET_H

#include <string>

#include "LLVMObjectTarget.h"

class CoffTarget : public LLVMObjectTarget {
public:
    static CoffTarget* CreateCoffTarget(std::string f, const llvm::Target *T);
    virtual ~CoffTarget(void) {};
private:
    CoffTarget();
protected:
  CoffTarget(const std::string &modname, llvm::object::ObjectFile *of): LLVMObjectTarget(modname, of) {};
};

#endif
