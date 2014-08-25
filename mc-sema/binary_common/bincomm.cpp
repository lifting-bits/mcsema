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
#include "bincomm.h"
#include "ELFTarget.h"
#include <LExcn.h>
#include "../common/to_string.h"
#include "llvm/ADT/StringSwitch.h"
#include <boost/filesystem.hpp> 

//PE file headers
#include "pe-parse/parser-library/parse.h"

//COFF file headers
#include "llvm/Object/COFF.h"
#include <algorithm>

using namespace std;
using namespace llvm;
using namespace boost;

enum UnderlyingTarget {
  PE_TGT,
  ELF_TGT,
  COFF_TGT,
  RAW_TGT,
  UNK_TGT
};

class PeTarget : public ExecutableContainer {
  parsed_pe *pe;
  string    mod_name;
public:
  PeTarget(string f, const Target *T);
  virtual ~PeTarget(void);
  virtual bool is_open(void);
  virtual bool find_import_name(uint32_t, string &);
  virtual bool get_exports(list<pair<string, VA> >  &);
  virtual bool is_addr_relocated(uint32_t);
  virtual bool relocate_addr(VA, VA&);
  virtual bool get_sections(vector<SectionDesc>  &);
  virtual string name(void) { return this->mod_name; }
  virtual ::uint64_t getBase(void) const;
  virtual ::uint64_t getExtent(void) const;
  virtual int readByte(::uint64_t, uint8_t *) const;
};

class CoffTarget : public ExecutableContainer {
  string                    mod_name;
  //(a, b) -- a is offset to apply to base of secT to get its real base
  //len remainds the same

  object::COFFObjectFile    *coff;
  VA                        baseAddr;
  VA                        extent;
public:
  typedef pair<boost::uint64_t, object::SectionRef>  secT;
  CoffTarget(string f, const Target *T);
  virtual ~CoffTarget(void);
  virtual bool is_open(void);
  virtual bool get_exports(list<pair<string, VA> > &);
  virtual bool find_import_name(uint32_t, string &);
  virtual bool is_addr_relocated(uint32_t);
  virtual bool relocate_addr(VA, VA &);
  virtual bool get_sections(vector<SectionDesc>  &);
  virtual string name(void) { return this->mod_name; }
  virtual ::uint64_t getBase(void) const;
  virtual ::uint64_t getExtent(void) const;
  virtual int readByte(::uint64_t, uint8_t *) const;
private:
  vector<secT>              secs;
};

CoffTarget::CoffTarget(string f, const Target *T) {
  OwningPtr<MemoryBuffer>	buff;
  llvm::error_code			ec = MemoryBuffer::getFile(f, buff);
  LASSERT(!ec, ec.message());

  this->mod_name = filesystem::path(f).stem().string();
  this->coff = new object::COFFObjectFile(buff.take(), ec);
  if(ec) throw LErr(__LINE__, __FILE__, ec.message());

  if(this->coff) {
    //build up a list of section objects and their 
    //adjusted base addresses
    //we need to do this because object files will 
    //frequently be laid out such that their segments
    //overlap, so we need to perform an amount of linking to
    //deal with it
    llvm::error_code  secIterErr; 

    bool  setBase = false;
    bool  setExtent = false;
    for(object::section_iterator  s = this->coff->begin_sections(),
        end = this->coff->end_sections();
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
        ::uint64_t            secOffset = (*it).first;
        object::SectionRef  containedSec = (*it).second;
        VA                  containedSecLow,containedSecHigh;
        
        e = containedSec.getAddress((::uint64_t&)containedSecLow);
        if(e) throw LErr(__LINE__, __FILE__, e.message());

        e = containedSec.getSize((::uint64_t &)containedSecHigh);
        if(e) throw LErr(__LINE__, __FILE__, e.message());

        containedSecLow += secOffset;
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

  return;
}

CoffTarget::~CoffTarget(void) {
  delete this->coff;
}

bool CoffTarget::is_open(void) {
  return this->coff != NULL;
}

bool CoffTarget::get_sections(vector<SectionDesc>  &secs) {

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

static
string getSymForRelocAddr(llvm::object::SectionRef      &sr,
                          uint32_t                      off, 
                          VA                            address, 
                          bool                          onlyFuncs) 
{
        llvm::error_code            e;
        llvm::object::relocation_iterator rit = sr.begin_relocations();
        while( rit != sr.end_relocations() ) {
            llvm::object::RelocationRef   rref = *rit;
            llvm::object::SymbolRef       symref;
            VA                            addr = 0;
            ::uint64_t                      type = 0;
            llvm::object::SymbolRef::Type symType;

            e = rref.getAddress((::uint64_t &)addr);
            LASSERT(!e, "Can't get address for relocation ref");

            e = rref.getType(type);
            LASSERT(!e, "Can't get type for relocation ref");
            e = rref.getSymbol(symref);
            LASSERT(!e, "Can't get symbol for relocation ref");
            e = symref.getType(symType);
            LASSERT(!e, "Can't get symbol type");

            string      st;
            llvm::StringRef strr(st);
            e = symref.getName(strr);
            LASSERT(!e, "Can't get name for symbol ref");
            
            if( address == (addr+off) ) {
                if(onlyFuncs) {
                  //it's a function (really an import..) if the type is UNK
                  if(symType == llvm::object::SymbolRef::ST_Unknown ||
                     symType == llvm::object::SymbolRef::ST_Other ) {
                    return strr.str();
                  }
                } else {
                  return strr.str();
                }
            }

            rit.increment(e);
            if( e ) {
                break;
            }
        }

    return "";
}

// get adjustment necessary to map a section's va in case of
// overlapped sections
static
bool getOffsetForSection(vector<CoffTarget::secT> &secs, 
        const llvm::object::SectionRef &sec_ref,
        ::uint64_t &offt)
{
  for(vector<CoffTarget::secT>::iterator it = secs.begin(), en = secs.end();
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
bool getSectionForAddr(vector<CoffTarget::secT> &secs, 
        uint32_t addr, 
        object::SectionRef &secref,
        uint32_t &offt) {
  //get the offset for this address
  for(vector<CoffTarget::secT>::iterator it = secs.begin(), en = secs.end();
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

bool CoffTarget::find_import_name(uint32_t lookupAddr, string &symname) {
  LASSERT(this->coff != NULL, "COFF not initialized");

  uint32_t  offt;
  VA        dummy;
  object::SectionRef section;
  bool      found_offt = getSectionForAddr(this->secs, lookupAddr, section, offt);
  LASSERT(found_offt, "Address "+to_string<uint32_t>(lookupAddr, hex) + " not found");

  symname = getSymForRelocAddr(section, offt, lookupAddr, true);

  // externals should be outside the relocation range
  return symname.size() != 0 && false == this->relocate_addr(((VA)lookupAddr), dummy);
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

bool CoffTarget::is_addr_relocated(uint32_t address) {
  LASSERT(this->coff != NULL, "COFF not initialized");

  //bool      found_offt = getOffsetForAddr(this->secs, address, offt);
  object::SectionRef section;
  uint32_t offt = 0;
  bool      found_sec = getSectionForAddr(this->secs, address, section, offt);

  LASSERT(found_sec, "Address " + to_string<uint32_t>(address, hex) + " not found");

  return isAddrRelocated(section, offt, address);
}

static
::uint64_t getAddressForString(object::COFFObjectFile &k, 
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
      ::uint64_t  addr = 0;

      ec = i->getAddress(addr);

      if( ec ) {
        return 0;
      }

      if(addr == object::UnknownAddressOrSize) {
        return 0;
      }

      // get which section this symbol references.
      ec = i->getSection(symbol_sec);

      if(ec) {
        return 0;
      }
      
      return addr;

    }
  }
  return 0;
}

bool CoffTarget::relocate_addr(VA addr, VA &toAddr) {
  LASSERT(this->coff != NULL, "COFF not initialized");

  uint32_t  offt;
  llvm::object::SectionRef section;
  bool      found_offt = getSectionForAddr(this->secs, addr, section, offt);

  //LASSERT(found_offt, "Address " + to_string<uint32_t>(addr, hex) + " not found");
  if (found_offt == false) 
  {
      return false;
  }

  string  s = getSymForRelocAddr(section, offt, addr, false);
  if (s == "") {
    return false;
    //    LASSERT(s.size() != 0, "Symbol not found");
  }

  llvm::object::section_iterator sym_sec = this->coff->end_sections();
  ::int64_t found = getAddressForString(*this->coff, s, sym_sec);

  if(sym_sec != this->coff->end_sections()) {
      ::uint64_t sec_offt;
      // get offset for the section *the symbol points to*,
      // not where it is located
      if(true == getOffsetForSection(this->secs, *sym_sec, sec_offt))
      {
          StringRef sn;
          sym_sec->getName(sn);
          found += sec_offt;
      } else {
          return false;
      }
  }

  if(found == 0) {
    return false;
  } else {
    toAddr = (VA)found;
  }

  return true;
}

::uint64_t CoffTarget::getBase(void) const {
  LASSERT(this->coff != NULL, "COFF not initialized");

  return this->baseAddr;
}

::uint64_t CoffTarget::getExtent(void) const {
  LASSERT(this->coff != NULL, "COFF not initialized");

  return this->extent;
}

bool CoffTarget::get_exports(list<pair<string,VA> >  &l) { 
  //get all the symbols from all the sections 

  for(vector<secT>::iterator it = this->secs.begin(), en = this->secs.end();
      it != en;
      ++it)
  {
    ::uint64_t            op = (*it).first;
    object::SectionRef  sr = (*it).second;
    ::uint64_t            low,high;
    llvm::error_code    e;

    e = sr.getAddress(low);

    LASSERT(!e, e.message());
    
    low += op; 
    e = sr.getSize(high);

    LASSERT(!e, e.message());

    high += low;

    llvm::error_code  iterErr;
    for(object::symbol_iterator si = this->coff->begin_symbols(),
        es = this->coff->end_symbols();
        !iterErr && si != es;
        si.increment(iterErr))
    {
      object::SymbolRef sym = *si;
      bool              res; 
      e = sr.containsSymbol(sym, res);

      LASSERT(!e, e.message());
      
      if(res) {
        StringRef str;
        VA        addr;
        e = sym.getName(str);
        LASSERT(!e, e.message());
        e = sym.getAddress((::uint64_t &)addr);
        LASSERT(!e, e.message());
        //so we know that this symbol is in this section, and, it has 
        //the offset given by op. add the offset...
        
        l.push_back(pair<string, VA>(str.str(), addr+op));
      }
    }
  }

  return true;
}

int CoffTarget::readByte(::uint64_t addr, uint8_t *byte) const {
  assert(this->coff != NULL);

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

PeTarget::PeTarget(string f, const Target *T) {
  this->mod_name = filesystem::path(f).stem().string();
  this->pe = ParsePEFromFile(f.c_str());
  return;
}

PeTarget::~PeTarget(void) {
  if(this->pe != NULL) {
    DestructParsedPE(this->pe);
    this->pe = NULL;
  }
  return;
}

bool PeTarget::is_open(void) {
  return this->pe != NULL;
}

//helper visitor for find_import_name
struct visit_imps_ctx {
  string  foundStr;
  VA      addrSearch;
};

static
int visit_imps(void *ctx, VA addr, string &module, string &symbol) {
  visit_imps_ctx  *c = (visit_imps_ctx *)ctx;

  if(c->addrSearch == addr) {
    //c->foundStr = module + "!" + symbol;
    c->foundStr = symbol;
    return 1;
  }

  return 0;
}

struct visit_exp_ctx {
  list<pair<string, VA> > &lst;
};

static
int visit_exp(void *ctx, VA addr, string &module, string &symbol) {
  visit_exp_ctx *c = (visit_exp_ctx *)ctx; 

  c->lst.push_back(pair<string, VA>(symbol, addr));

  return 0;
}

bool PeTarget::get_exports(list<pair<string, VA> > &l) { 
  //start with the PE entry point symbol
  if(this->pe == NULL) {
    return false;
  }

  VA  t;
  if(GetEntryPoint(this->pe, t)) {
    l.push_back(pair<string, ::uint64_t>("entry", t));
  }

  visit_exp_ctx c = { l };

  //enumerate over the EAT of the supplied module
  IterExpVA(this->pe, visit_exp, &c);

  return true;
}

bool PeTarget::find_import_name(uint32_t location, string &impname) {
  if(this->pe == NULL) {
    return false;
  }

  visit_imps_ctx  c;

  uint8_t   a1,a2,a3,a4;

  if(ReadByteAtVA(this->pe, location, a1) == false) {
    return false;
  }

  if(ReadByteAtVA(this->pe, location+1, a2) == false) {
    return false;
  }

  if(ReadByteAtVA(this->pe, location+2, a3) == false) {
    return false;
  }

  if(ReadByteAtVA(this->pe, location+3, a4) == false) {
    return false;
  }

  c.foundStr = "";
  c.addrSearch = (a4 << 24) + (a3 << 16) + (a2 << 8) + a1;
  IterImpVAString(this->pe, visit_imps, &c);

  if(c.foundStr.size() > 0) {
    impname = c.foundStr;
    return true;
  }

  return false;
}

//helper visitor for is_addr_relocated

struct visit_rels_ctx {
  VA    addr;
  bool  found;
};

static
int visit_rels(void *ctx, VA addr, reloc_type t) {
  visit_rels_ctx *c = (visit_rels_ctx *)ctx;

  if(c->addr == addr) {
    c->found = true;
    return 1;
  }

  return 0;
}

bool PeTarget::is_addr_relocated(uint32_t addr) {
  if(this->pe == NULL) {
    return false;
  }

  visit_rels_ctx  c;

  c.found = false;
  c.addr = addr;

  IterRelocs(this->pe, visit_rels, &c);

  return c.found;
}

bool PeTarget::relocate_addr(VA addr, VA &toaddr) {
  //doesn't really need to do anything...
  if(!this->is_addr_relocated(addr)) {
      return false;
  }

  uint8_t b[4];

  for(int i = 0; i < 4; i++) {
      if( !ReadByteAtVA(this->pe, addr+i, b[i]) ) {
          return false;
      }
  }

  toaddr =  (VA)  (((uint32_t)b[3] << 24) | 
                  ((uint32_t)b[2] << 16) |
                  ((uint32_t)b[1] <<  8) |
                  ((uint32_t)b[0] <<  0));


  return true;
}

struct get_sects_ctx {
  vector<ExecutableContainer::SectionDesc> &s;
  parsed_pe *pe;
};

struct add_rels_to_vector_ctx {
  VA base;
  VA size;
  vector<VA> &rels;
};

static
int add_rels_to_vector(void *ctx, VA addr, reloc_type t) {
  add_rels_to_vector_ctx *c = (add_rels_to_vector_ctx *)ctx;

  VA base = c->base;
  VA limit = c->base + c->size;
  if(addr >= base && addr < limit) {
      c->rels.push_back(addr);
  }

  return 0;
}

int get_secs_cb(void                  *ctx,
                VA                    base,
                string                &secName,
                image_section_header  s,
                bounded_buffer        *B)
{
  get_sects_ctx                     *C = (get_sects_ctx *)ctx;
  ExecutableContainer::SectionDesc  d;

  d.secName = secName;
  d.base = base;

  // section is code if it is executable OR if it is code
  if( (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 ||
      (s.Characteristics & IMAGE_SCN_CNT_CODE) != 0 ) {
    d.type = ExecutableContainer::CodeSection;
  } else {
    d.type = ExecutableContainer::DataSection;
  }

  d.read_only = (s.Characteristics & IMAGE_SCN_MEM_WRITE) == 0;

  for(::uint64_t i = 0; i < bufLen(B); i++) {
    uint8_t b;

    bool res = readByte(B, i, b);
    LASSERT(res, "Failed to read");
    d.contents.push_back(b);
  }

  add_rels_to_vector_ctx adrv = 
    { d.base,
      d.contents.size(),
      d.reloc_addrs
    };

  IterRelocs(C->pe, add_rels_to_vector, &adrv);

  std::sort(d.reloc_addrs.begin(), d.reloc_addrs.end());
  C->s.push_back(d);

  return 0;
}

bool PeTarget::get_sections(vector<SectionDesc>  &secs) {
  if(this->pe == NULL) {
    return false;
  }

  get_sects_ctx c = {secs, this->pe};
  IterSec(this->pe, get_secs_cb, &c);

  return true;
}

struct visit_sec_ctx {
  ::uint64_t  curLowest;
  bool      curLowestClear;
};

static
int visit_sec(void                  *ctx, 
              VA                    secBase, 
              string                &secName, 
              image_section_header  s, 
              bounded_buffer        *B) 
{
  visit_sec_ctx *c = (visit_sec_ctx *)ctx;

  if(c->curLowestClear == true) {
    c->curLowestClear = false;
    c->curLowest = secBase;
  } else {
    if(secBase < c->curLowest ) {
      c->curLowest = secBase;
    }
  }

  return 0;
}

::uint64_t PeTarget::getBase(void) const {
  assert(this->pe != NULL);

  //get the lowest base address for any section
  visit_sec_ctx c;

  c.curLowest = 0;
  c.curLowestClear = true;

  IterSec(this->pe, visit_sec, &c);

  return c.curLowest;
}

static
int visit_sec_len(void                  *ctx, 
                  VA                    secBase, 
                  string                &secName, 
                  image_section_header  s,
                  bounded_buffer        *B) 
{
  ::uint64_t  *len = (::uint64_t *)ctx;

  *len += bufLen(B);

  return 0;
}

::uint64_t PeTarget::getExtent(void) const {
  assert(this->pe != NULL);

  //count the sizes of all of the sections
  //this kind of assumes that they are contiguous
  //with no gaps, but, whatever. it is an imperfect
  //fit for an imperfect problem
  ::uint64_t  len = 0;
  IterSec(this->pe, visit_sec_len, &len);

  return len;
}

int PeTarget::readByte(::uint64_t addr, uint8_t *byte) const {
  assert(this->pe != NULL);
  uint8_t b;

  //just shell out to our API that does this from PE lib
  if(ReadByteAtVA(this->pe, addr, b)) {
    *byte = b;
    return 0;
  } 

  return -1;
}

UnderlyingTarget targetFromExtension(string extension) {
  UnderlyingTarget  t = StringSwitch<UnderlyingTarget>(extension)
    .Case(".obj", COFF_TGT)
    .Case(".exe", PE_TGT)
    .Case(".dll", PE_TGT)
    .Case(".so", ELF_TGT)
    .Case(".o", ELF_TGT)
    .Case(".bin", RAW_TGT)
    .Default(UNK_TGT);

  LASSERT(t != UNK_TGT, "Unknown extension: "+extension);

  return t;
}

ExecutableContainer *ExecutableContainer::open(string f, const Target *T) {
  filesystem::path  p(f);
  p = filesystem::canonical(p);
  filesystem::path  extPath = p.extension();

  UnderlyingTarget t = targetFromExtension(extPath.string());

  switch(t) {
    case PE_TGT:
      return new PeTarget(p.string(), T);
      break;

    case COFF_TGT:
      return new CoffTarget(p.string(), T);
      break;

    case ELF_TGT:
      return new ElfTarget(p.string(), T);
      break;

    case UNK_TGT:
    case RAW_TGT:
      throw LErr(__LINE__, __FILE__, "Unsupported format, NIY");
      break;
  }

  return NULL;
}
