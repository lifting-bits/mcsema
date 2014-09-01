#include <string>

#include <LExcn.h>
#include <boost/filesystem.hpp> 

#include "llvm/Support/TargetRegistry.h"

#include "COFFTarget.h"


using namespace llvm;
using namespace std;
using namespace boost;

CoffTarget* CoffTarget::CreateCoffTarget(string f, const Target *T) 
{
    OwningPtr<MemoryBuffer>	buff;
    llvm::error_code			ec = MemoryBuffer::getFile(f, buff);
    LASSERT(!ec, ec.message());

    std::string mn = filesystem::path(f).stem().string();
    llvm::object::ObjectFile *objf =
        new object::COFFObjectFile(buff.take(), ec);

    return new CoffTarget(mn, objf);
}
