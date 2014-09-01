#include "bincomm.h"
#include <LExcn.h>
#include "LLVMObjectTarget.h"
#include <algorithm>


class ElfTarget : public LLVMObjectTarget {
public:
    static ElfTarget* CreateElfTarget(std::string f, const llvm::Target *T);
    virtual ~ElfTarget(void) {};
private:
    ElfTarget();
protected:
  ElfTarget(const std::string &modname, llvm::object::ObjectFile *of): LLVMObjectTarget(modname, of) {};
};

//class ElfTarget : public ExecutableContainer {
//    std::string                    mod_name;
//
//    llvm::object::ELFObjectFile<llvm::support::little, false>    *elf;
//    VA                        baseAddr;
//    VA                        extent;
//    public:
//
//        ElfTarget(std::string f, const llvm::Target *T);
//
//        typedef std::pair<boost::uint64_t, llvm::object::SectionRef>  secT;
//
//        virtual ~ElfTarget(void);
//        virtual bool is_open(void);
//        virtual bool get_exports(std::list<std::pair<std::string, VA> > &);
//        virtual bool find_import_name(uint32_t, std::string &);
//        virtual bool is_addr_relocated(uint32_t);
//        virtual bool relocate_addr(VA, VA &);
//        virtual bool get_sections(std::vector<ExecutableContainer::SectionDesc>  &);
//        virtual std::string name(void) { return this->mod_name; }
//        virtual ::uint64_t getBase(void) const;
//        virtual ::uint64_t getExtent(void) const;
//        virtual int readByte(::uint64_t, boost::uint8_t *) const;
//    private:
//        std::vector<secT>              secs;
//};
