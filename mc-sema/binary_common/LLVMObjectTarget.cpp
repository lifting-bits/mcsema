/*
Copyright (c) 2014, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of Trail of Bits nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <string>
#include <vector>
#include <list>

#include <LExcn.h>
#include <algorithm>
#include <boost/filesystem.hpp> 

#include "llvm/Support/TargetRegistry.h"

#include "bincomm.h"
#include "LLVMObjectTarget.h"
#include "../common/to_string.h"
#include "llvm/Support/Debug.h"
#include "llvm/ADT/SmallString.h"

using namespace llvm;
using namespace std;
using namespace boost;


LLVMObjectTarget::LLVMObjectTarget(const std::string &modname, llvm::object::ObjectFile *of) : mod_name(modname)
{
    //build up a list of section objects and their 
    //adjusted base addresses
    //we need to do this because object files will 
    //frequently be laid out such that their segments
    //overlap, so we need to perform an amount of linking to
    //deal with it
    llvm::error_code  secIterErr; 
    LASSERT(of!=NULL, "Cannot pass NULL object file to constructor");
    this->objectfile = of;

    bool  setBase = false;
    bool  setExtent = false;
    for(object::section_iterator  s = this->objectfile->begin_sections(),
        end = this->objectfile->end_sections();
        !secIterErr && s != end;
        s.increment(secIterErr))
    {
      object::SectionRef  sr = *s;
      VA                  low,high;
      llvm::error_code    e;

      bool                isText,isData,isBSS,isRequired;
      //only get segments if they are text, data, or bss
      e = sr.isText(isText);
      if(e) throw LErr(__LINE__, __FILE__, e.message());
      e = sr.isData(isData);
      if(e) throw LErr(__LINE__, __FILE__, e.message());
      e = sr.isBSS(isBSS);
      if(e) throw LErr(__LINE__, __FILE__, e.message());
      e = sr.isRequiredForExecution(isRequired);
      if(e) throw LErr(__LINE__, __FILE__, e.message());


      if( (isText == false && isData == false && isBSS == false) || isRequired == false) {
        continue;
      }       
      e = sr.getAddress((::uint64_t &)low);
      if(e) throw LErr(__LINE__, __FILE__, e.message());

      e = sr.getSize((::uint64_t &)high);
      if(e) throw LErr(__LINE__, __FILE__, e.message());
      high += low;

      ::uint64_t  m1 = low,m2 = high;
      //does this overlap with something already in secs
      ::uint64_t  overlapAdj = 0;
      for(vector<secT>::iterator it = this->secs.begin(), en = this->secs.end();
          it != en;
          ++it)
      {
        ::uint64_t            seelfset = (*it).first;
        object::SectionRef  containedSec = (*it).second;
        VA                  containedSecLow,containedSecHigh;
        
        e = containedSec.getAddress((::uint64_t&)containedSecLow);
        if(e) throw LErr(__LINE__, __FILE__, e.message());

        e = containedSec.getSize((::uint64_t &)containedSecHigh);
        if(e) throw LErr(__LINE__, __FILE__, e.message());

        containedSecLow += seelfset;
        containedSecHigh += containedSecLow;
        
        //does overlap?
        if(containedSecLow < m2 && m1 < containedSecHigh) {
          //how much to add to containedSecLow to make it not overlap?
          overlapAdj = (containedSecHigh-low);
          m1 += overlapAdj;
          m2 += overlapAdj;
        } 
      }

      if(setBase == false) {
        this->baseAddr = low+overlapAdj;
      } else {
        if(this->baseAddr > low+overlapAdj) {
          this->baseAddr = low+overlapAdj;
        }
      }

      if(setExtent == false) {
        this->extent = high+overlapAdj;
      } else {
        if(this->extent < high+overlapAdj) {
          this->extent = high+overlapAdj;
        }
      }

      this->secs.push_back(secT(overlapAdj, sr));
    }
}

LLVMObjectTarget::~LLVMObjectTarget(void) {
  delete this->objectfile;
}

bool LLVMObjectTarget::is_open(void) {
  return this->objectfile != NULL;
}


bool LLVMObjectTarget::get_exports(list<pair<string,VA> >  &l) { 
  //get all the symbols from all the sections 

  for(vector<secT>::iterator it = this->secs.begin(), en = this->secs.end();
      it != en;
      ++it)
  {
    ::uint64_t            op = (*it).first;
    object::SectionRef  sr = (*it).second;
    llvm::error_code    e;
    StringRef secName;


    e = sr.getName(secName);
    LASSERT(!e, e.message());

    dbgs() << "Looking at Object File section: " << secName << "\n";

    llvm::error_code  iterErr;
    for(object::symbol_iterator si = this->objectfile->begin_symbols(),
        es = this->objectfile->end_symbols();
        !iterErr && si != es;
        si.increment(iterErr))
    {
        object::SymbolRef sym = *si;
        bool              res = false; 
        StringRef str;
        e = sym.getName(str);

        e = sr.containsSymbol(sym, res);

        LASSERT(!e, e.message());

        if(res) {
            VA        addr;
            e = sym.getName(str);
            LASSERT(!e, e.message());
            e = sym.getAddress((::uint64_t &)addr);
            LASSERT(!e, e.message());
            //so we know that this symbol is in this section, and, it has 
            //the offset given by op. add the offset...

            dbgs() << "Found symbol: " << str << " in " << secName << "\n";
            l.push_back(pair<string, VA>(str.str(), addr+op));
        }
    }
  }

  return true;
}

static bool getRelocForAddr(llvm::object::SectionRef    &sr, 
                            uint32_t                    off, 
                            VA                          address,
                            llvm::object::RelocationRef &rr)
{
        llvm::error_code            e;
        llvm::object::relocation_iterator rit = sr.begin_relocations();
        while( rit != sr.end_relocations() ) {
            rr = *rit;
            llvm::object::SymbolRef       symref;
            VA                            addr = 0;

            e = rr.getAddress((::uint64_t &)addr);
            LASSERT(!e, "Can't get address for relocation ref");
            //llvm::dbgs() << "\t" << __FUNCTION__ << ": Testing " << to_string<VA>(address, hex) 
            //           << " vs. " << to_string<VA>(addr+off, hex) << "\n";

            if( address == (addr+off) ) {
                return true;
            }

            rit.increment(e);
            if( e ) {
                break;
            }
        }

        return false;
}


static
string getSymForReloc(llvm::object::RelocationRef &rref,
                      bool                        onlyFuncs) 
{
    llvm::error_code            e;
    llvm::object::SymbolRef       symref;
    llvm::object::SymbolRef::Type symType;
    std::string rt = "";

    e = rref.getSymbol(symref);
    LASSERT(!e, "Can't get symbol for relocation ref");
    e = symref.getType(symType);
    LASSERT(!e, "Can't get symbol type");

    llvm::StringRef strr;
    e = symref.getName(strr);
    LASSERT(!e, "Can't get name for symbol ref");

    if(onlyFuncs) {
        //it's a function (really an import..) if the type is UNK
        if(symType == llvm::object::SymbolRef::ST_Unknown ||
                symType == llvm::object::SymbolRef::ST_Other ||
                symType == llvm::object::SymbolRef::ST_Function ) {
            rt = strr.str();
        }
    } else {
        rt = strr.str();
    }

    return rt;
}


static
string getSymForRelocAddr(llvm::object::SectionRef      &sr,
                          uint32_t                      off, 
                          VA                            address, 
                          bool                          onlyFuncs) 
{
    
      llvm::object::RelocationRef   rref;
      if(!getRelocForAddr(sr, off, address, rref)) {
          return "";
      }

    return getSymForReloc(rref, onlyFuncs);
}

static
bool getSectionForAddr(vector<LLVMObjectTarget::secT> &secs, 
        uint32_t addr, 
        object::SectionRef &secref,
        uint32_t &offt) 
{
  //get the offset for this address
  for(vector<LLVMObjectTarget::secT>::iterator it = secs.begin(), en = secs.end();
      it != en;
      ++it)
  {
    ::uint64_t            op = (*it).first;
    object::SectionRef  sr = (*it).second;
    ::uint64_t            low,high; 
    llvm::error_code    e;
    StringRef sn;

    e = sr.getAddress(low);

    LASSERT(!e, e.message());
    
    low += op; 
    e = sr.getSize(high);

    LASSERT(!e, e.message());

    high += low;

    if(addr >= low && addr < high) {
        secref = sr;
        offt = (uint32_t)op;
      return true;
    }
  }

  return false;
}

bool LLVMObjectTarget::find_import_name(uint32_t lookupAddr, std::string &symname) {
  LASSERT(this->objectfile != NULL, "Object File not initialized");

  uint32_t  offt;
  VA        dummy;
  object::SectionRef section;
  bool      found_offt = getSectionForAddr(this->secs, lookupAddr, section, offt);
  LASSERT(found_offt, "Address "+to_string<uint32_t>(lookupAddr, hex) + " not found");

  symname = getSymForRelocAddr(section, offt, lookupAddr, true);

  llvm::error_code e;
  bool is_text_ref;
  e = section.isText(is_text_ref);
  LASSERT(!e, e.message());

  bool can_reloc = this->relocate_addr(((VA)lookupAddr), dummy);

  // if we *can't* relocate this to a sane address, its probably an import
  return (symname.size() != 0 && false == can_reloc) ||
      ((uint32_t)dummy == 0xFFFFFFFF);
}

static
bool isAddrRelocated(const object::SectionRef &sr, uint32_t offt, VA address) {

    llvm::object::relocation_iterator rit = sr.begin_relocations();
    llvm::error_code    e;

    while( rit != sr.end_relocations() ) {
      llvm::object::RelocationRef   rref = *rit;
      llvm::object::SymbolRef     symref;
      VA                          addr = 0;

      e = rref.getAddress((::uint64_t &)addr);
      LASSERT(!e, e.message()); 

      e = rref.getSymbol(symref);
      LASSERT(!e, e.message());

      if( address == (offt+addr) ) {
        StringRef symname;
        //get the symbol for the address?
        llvm::object::SymbolRef::Type t;
        uint32_t                      flag;
        //check and see if the symbols type is a global ... 
        e = symref.getType(t);
        LASSERT(!e, e.message());
        e = symref.getFlags(flag);
        LASSERT(!e, e.message());


        symref.getName(symname);

        SmallString<32> relocType;
        e = rref.getTypeName(relocType);
        LASSERT(!e, e.message());
        // shortcut for ELF relocations by type
        // TODO: move this to ELF speific code
        if(relocType == "R_386_32" ||
           relocType == "R_386_PC32") {
            return true;
        }


        bool t1 = (t == llvm::object::SymbolRef::ST_Data);
        bool t2 = 0 != (flag | llvm::object::SymbolRef::SF_Global);

        if( (t1 && t2) || 
            (t == llvm::object::SymbolRef::ST_Other) ||
            (t == llvm::object::SymbolRef::ST_Unknown) )
        {
          return true;
        }
      }

      rit.increment(e);

      LASSERT(!e, e.message());
    }

  return false;
}

bool LLVMObjectTarget::is_addr_relocated(uint32_t address) {
  LASSERT(this->objectfile != NULL, "Object File not initialized");

  object::SectionRef section;
  uint32_t offt = 0;
  bool      found_sec = getSectionForAddr(this->secs, address, section, offt);

  LASSERT(found_sec, "Address " + to_string<uint32_t>(address, hex) + " not found");

  return isAddrRelocated(section, offt, address);
}

// get adjustment necessary to map a section's va in case of
// overlapped sections
static
bool getOffsetForSection(vector<LLVMObjectTarget::secT> &secs, 
        const llvm::object::SectionRef &sec_ref,
        ::uint64_t &offt)
{
  for(vector<LLVMObjectTarget::secT>::iterator it = secs.begin(), en = secs.end();
      it != en;
      ++it)
  {
    ::uint64_t            op = (*it).first;
    object::SectionRef  sr = (*it).second;
    if(sr == sec_ref) {
        offt = op;
        return true;
    }
  }

  return false; 
}

static
::int64_t getAddressForString(object::ObjectFile &k, 
        string callTarget,
        llvm::object::section_iterator &symbol_sec) {
  //walk all the symbols
  llvm::error_code              ec;
  llvm::StringRef               sr(callTarget);


  for(llvm::object::symbol_iterator i=k.begin_symbols(),e=k.end_symbols();
    i != e;
    i.increment(ec))
  {
    llvm::StringRef curName;

    if( ec ) {
      break;
    }

    ec = i->getName(curName);

    if( ec ) {
      break;
    }

    if( curName == sr ) {
      ::uint64_t  addr = -1;

      ec = i->getAddress(addr);

      if( ec ) {
        return -1;
      }

      if(addr == object::UnknownAddressOrSize) {
        return -1;
      }

      // get which section this symbol references.
      ec = i->getSection(symbol_sec);

      if(ec) {
        return -1;
      }
      
      return (::int64_t)addr;

    }
  }
  return -1;
}

bool LLVMObjectTarget::relocate_addr(VA addr, VA &toAddr) {

  LASSERT(this->objectfile != NULL, "Object File not initialized");

  // this is messy.
  // First, we need to figure out which section this VA is in.
  // This isn't easy because some file VAs may overlap
  // 
  // The relocation entry will point to a symbol. We will then
  // need to find the symbol's address in whatever section it may be.
  // There is a similar problem of overlaps.
  //
  // Finally, some relocation types are relative to the original data
  // at the point of the relocation. So we need to read section data
  // and manually add it to the resolved symbol address

  uint32_t  offt;
  llvm::object::SectionRef section;
  llvm::error_code    e;

  // step 1: find which section this address lives in. This can be kind of hard when multiple things
  // map at address 0x0, which happens sometimes. Store (addr - [base of section]) in offt
  bool      found_offt = getSectionForAddr(this->secs, addr, section, offt);

  if (found_offt == false) 
  {
      // its not in a section. this is bad.
      llvm::dbgs() << __FUNCTION__ << ": Could not find section for: " 
                   << to_string<VA>(addr, hex) << "\n";
      return false;
  } else {
      StringRef secName;
      section.getName(secName);
      llvm::dbgs() << __FUNCTION__ << ": Relocation lives in: " << secName.str() << "\n";
      llvm::dbgs() << __FUNCTION__ << ": Offset is: " << to_string<VA>(offt, hex) << "\n";
  }

  // get a relocation reference for this address. this is how we
  // will find the relocation type and also the offset of the
  // relocation from its section base
  llvm::object::RelocationRef rref;
  if(!getRelocForAddr(section, offt, addr, rref)) {
      llvm::dbgs() << __FUNCTION__ << ": Could not find reloc ref for: " 
                   << to_string<VA>(addr, hex) << "\n";
      return false;
  }

  // lets find out what kind of relocation we have
  SmallString<32> relocType;
  e = rref.getTypeName(relocType);
  LASSERT(!e, e.message());

  VA offt_from_sym = 0;

  llvm::dbgs() << __FUNCTION__ << ": Looking at relocation type: " << relocType << "\n";

  if(relocType == "R_386_32") {
      // these are absolute relocations and they are relative to 
      // the original bytes in the file. Lets read those bytes
      StringRef secContents;
      e = section.getContents(secContents);
      LASSERT(!e, "Can't get section data");

      ::uint64_t relo_offt;
      e = rref.getOffset(relo_offt);
      LASSERT(!e, "Can't get relocation offset");

      const uint8_t *data = (const uint8_t*)secContents.data();
    
      offt_from_sym = (VA)  
          (((uint32_t)data[relo_offt+3] << 24) | 
           ((uint32_t)data[relo_offt+2] << 16) | 
           ((uint32_t)data[relo_offt+1] <<  8) | 
           ((uint32_t)data[relo_offt+0] <<  0));

      llvm::dbgs() << __FUNCTION__ << ": Original bytes are: " << to_string<VA>(offt_from_sym, hex) << "\n";
  }

  // find what symbol name this relocation points to. 
  string  s = getSymForReloc(rref, false);
  if (s == "") {
    // Reloc is not bound to a symbol
    return false;
  }

  llvm::dbgs() << __FUNCTION__ << ": Relocation symbol is: " << s << "\n";

  llvm::object::section_iterator sym_sec = this->objectfile->end_sections();
  // get the address of the symbol name. No, we couldn't directly
  // get it from the SymbolRef that is attached to the RelocationRef.
  // Life is complicated.
  ::int64_t found = getAddressForString(*this->objectfile, s, sym_sec);
  llvm::dbgs() << __FUNCTION__ << ": Address of symbol is: " << to_string<VA>(found, hex) << "\n";

  if(found == -1) {
    return false;
  }

  // check if this symbol is in a section
  if(sym_sec != this->objectfile->end_sections()) {
      ::uint64_t sec_offt;
      // get offset for the section *the symbol points to*,
      // *NOT* the offset of the section the symbol is in
      if(true == getOffsetForSection(this->secs, *sym_sec, sec_offt))
      {
          StringRef sn;
          sym_sec->getName(sn);
          // symbol address is :
          // destination section base + symbol address
          llvm::dbgs() << __FUNCTION__ << ": Section base is: " << to_string< ::uint64_t>(sec_offt, hex) << "\n";
          found += sec_offt;
      } else {
          return false;
      }
  }

  // if this is an absolute relocation
  // add the original file bytes to the destination addr
  found += offt_from_sym;

  llvm::dbgs() << __FUNCTION__ << ": Final addr is: " << to_string<VA>(found, hex) << "\n";

  toAddr = (VA)found;

  return true;
}

bool LLVMObjectTarget::get_sections(vector<ExecutableContainer::SectionDesc>  &secs) {

  for(vector<secT>::iterator it = this->secs.begin(), en = this->secs.end();
      it != en;
      ++it)
  {
    secT                s = *it;
    ::uint64_t            offt = (*it).first;
    ::uint64_t            base;
    object::SectionRef  sr = (*it).second;
    llvm::error_code    e;
    SectionDesc         d;
    bool                isCode;
    StringRef           secName;

    e = sr.getAddress(base);

    if(e) throw LErr(__LINE__, __FILE__, e.message());

    base += offt;

    e = sr.isText(isCode);

    if(e) throw LErr(__LINE__, __FILE__, e.message());

    e = sr.getName(secName);

    if(e) throw LErr(__LINE__, __FILE__, e.message());

    StringRef contents;  

    e = sr.getContents(contents);
    if(e) throw LErr(__LINE__, __FILE__, e.message());
 
    d.secName = secName.str();
    d.base = base;
    if(isCode) {
      d.type = ExecutableContainer::CodeSection;
    } else {
      d.type = ExecutableContainer::DataSection;
    }

    bool isROData;
    e = sr.isReadOnlyData(isROData);

    if(e) throw LErr(__LINE__, __FILE__, e.message());
    d.read_only = isROData;
   
    const char  *dt = contents.data();
    for(uint32_t i = 0; i < contents.size(); i++) {
      d.contents.push_back(dt[i]);
    }

    object::relocation_iterator rit = sr.begin_relocations();
    while(rit != sr.end_relocations())
    {
        ::uint64_t reloc_addr;

        e = rit->getAddress(reloc_addr);

        if(e) throw LErr(__LINE__, __FILE__, e.message());
        d.reloc_addrs.push_back(reloc_addr);

        rit.increment(e);
        if(e) throw LErr(__LINE__, __FILE__, e.message());
    }

    // keep these sorted; other behavior relies on this
    std::sort(d.reloc_addrs.begin(), d.reloc_addrs.end());
    secs.push_back(d);
  }

  return true;
}

::uint64_t LLVMObjectTarget::getBase(void) const {
  LASSERT(this->objectfile != NULL, "Object File not initialized");

  return this->baseAddr;
}

::uint64_t LLVMObjectTarget::getExtent(void) const {
  LASSERT(this->objectfile != NULL, "Object File not initialized");

  return this->extent;
}

int LLVMObjectTarget::readByte(::uint64_t addr, uint8_t *byte) const {
  assert(this->objectfile != NULL);

  for(vector<secT>::const_iterator it = this->secs.begin(), en = this->secs.end();
      it != en;
      ++it)
  {
    ::uint64_t            off = (*it).first;
    object::SectionRef  sr = (*it).second;
    VA                  low,high;
    llvm::error_code    e; 

    e = sr.getAddress((::uint64_t &)low);
    LASSERT(!e, e.message());
    e = sr.getSize((::uint64_t &)high);
    LASSERT(!e, e.message());
    low += off;
    high += low;

    if(addr >= low && addr < high) {
      //it is in this section
      StringRef contents;  
      ::uint64_t  offset = addr - low;

      e = sr.getContents(contents);
      LASSERT(!e, e.message());
      *byte = contents.data()[offset];
      return 0;
    }
  }

  return -1;
}
