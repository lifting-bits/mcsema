#include <LExcn.h>
#include <boost/filesystem.hpp> 
#include "llvm/Object/ELF.h"
#include "llvm/Support/Endian.h"
#include "ELFTarget.h"

using namespace std;
using namespace llvm;
using namespace boost;

ElfTarget* ElfTarget::CreateElfTarget(string f, const Target *T) 
{
    OwningPtr<MemoryBuffer>	buff;
    llvm::error_code			ec = MemoryBuffer::getFile(f, buff);
    LASSERT(!ec, ec.message());

    std::string mn = filesystem::path(f).stem().string();
    llvm::object::ObjectFile *objf = 
        new llvm::object::ELFObjectFile<support::little, false> (buff.take(), ec);

    return new ElfTarget(mn, objf);
}
