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
#include "PETarget.h"
#include "bincomm.h"

using namespace llvm;
using namespace std;
using namespace boost;

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

