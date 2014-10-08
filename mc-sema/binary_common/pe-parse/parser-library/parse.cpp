/*
The MIT License (MIT)

Copyright (c) 2013 Andrew Ruef

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <list>
#include "parse.h"
#include "nt-headers.h"
#include <to_string.h>

using namespace std;
using namespace boost;

struct section {
  string                sectionName;
  ::uint32_t            sectionBase;
  bounded_buffer        *sectionData;
  image_section_header  sec;
};

struct importent {
  VA      addr;
  string  symbolName;
  string  moduleName;
};

struct exportent {
  VA      addr;
  string  symbolName;
  string  moduleName;
};

struct reloc {
  VA          shiftedAddr;
  reloc_type  type;
};

struct parsed_pe_internal {
  list<section>   secs;
  list<importent> imports;
  list<reloc>     relocs;
  list<exportent> exports;
};

bool getSecForVA(list<section> &secs, VA v, section &sec) {
  for(list<section>::iterator it = secs.begin(), e = secs.end();
      it != e;
      ++it)
  {
    section s = *it;
  
    ::uint32_t  low = s.sectionBase;
    ::uint32_t  high = low + s.sec.Misc.VirtualSize;

    if(v >= low && v < high) {
      sec = s;
      return true;
    }
  }

  return false;
}

bool getSections( bounded_buffer  *b, 
                  bounded_buffer  *fileBegin,
                  nt_header_32    &nthdr, 
                  list<section>   &secs) {
  if(b == NULL) {
    return false;
  }

  //get each of the sections...
  for(::uint32_t i = 0; i < nthdr.FileHeader.NumberOfSections; i++) {
    image_section_header  curSec;
    
    ::uint32_t  o = i*sizeof(image_section_header);
    for(::uint32_t k = 0; k < NT_SHORT_NAME_LEN; k++) {
      if(readByte(b, o+k, curSec.Name[k]) == false) {
        return false;
      }
    }
#define READ_WORD(x) \
  if(readWord(b, o+_offset(image_section_header, x), curSec.x) == false) { \
    return false; \
  } 
#define READ_DWORD(x) \
  if(readDword(b, o+_offset(image_section_header, x), curSec.x) == false) { \
    return false; \
  } 
 
    READ_DWORD(Misc.VirtualSize);
    READ_DWORD(VirtualAddress);
    READ_DWORD(SizeOfRawData);
    READ_DWORD(PointerToRawData);
    READ_DWORD(PointerToRelocations);
    READ_DWORD(PointerToLinenumbers);
    READ_WORD(NumberOfRelocations);
    READ_WORD(NumberOfLinenumbers);
    READ_DWORD(Characteristics);
#undef READ_WORD
#undef READ_DWORD

    //now we have the section header information, so fill in a section 
    //object appropriately
    section thisSec;
    for(::uint32_t i = 0; i < NT_SHORT_NAME_LEN; i++) {
      ::uint8_t c = curSec.Name[i];
      if(c == 0) {
        break;
      }

      thisSec.sectionName.push_back((char)c);
    }

    thisSec.sectionBase = nthdr.OptionalHeader.ImageBase+curSec.VirtualAddress;
    thisSec.sec = curSec;
    ::uint32_t  lowOff = curSec.PointerToRawData;
    ::uint32_t  highOff = lowOff+curSec.SizeOfRawData;
    thisSec.sectionData = splitBuffer(fileBegin, lowOff, highOff);
    
    secs.push_back(thisSec);
  }

  return true;
}

bool readOptionalHeader(bounded_buffer *b, optional_header_32 &header) {
#define READ_WORD(x) \
  if(readWord(b, _offset(optional_header_32, x), header.x) == false) { \
    return false; \
  } 
#define READ_DWORD(x) \
  if(readDword(b, _offset(optional_header_32, x), header.x) == false) { \
    return false; \
  } 
#define READ_BYTE(x) \
  if(readByte(b, _offset(optional_header_32, x), header.x) == false) { \
    return false; \
  }

  READ_WORD(Magic);

  if(header.Magic != NT_OPTIONAL_32_MAGIC) {
    return false;
  }

  READ_BYTE(MajorLinkerVersion);
  READ_BYTE(MinorLinkerVersion);
  READ_DWORD(SizeOfCode);
  READ_DWORD(SizeOfInitializedData);
  READ_DWORD(SizeOfUninitializedData);
  READ_DWORD(AddressOfEntryPoint);
  READ_DWORD(BaseOfCode);
  READ_DWORD(BaseOfData);
  READ_DWORD(ImageBase);
  READ_DWORD(SectionAlignment);
  READ_DWORD(FileAlignment);
  READ_WORD(MajorOperatingSystemVersion);
  READ_WORD(MinorOperatingSystemVersion);
  READ_WORD(MajorImageVersion);
  READ_WORD(MinorImageVersion);
  READ_WORD(MajorSubsystemVersion);
  READ_WORD(MinorSubsystemVersion);
  READ_DWORD(Win32VersionValue);
  READ_DWORD(SizeOfImage);
  READ_DWORD(SizeOfHeaders);
  READ_DWORD(CheckSum);
  READ_WORD(Subsystem);
  READ_WORD(DllCharacteristics);
  READ_DWORD(SizeOfStackReserve);
  READ_DWORD(SizeOfStackCommit);
  READ_DWORD(SizeOfHeapReserve);
  READ_DWORD(SizeOfHeapCommit);
  READ_DWORD(LoaderFlags);
  READ_DWORD(NumberOfRvaAndSizes);

#undef READ_WORD
#undef READ_DWORD
#undef READ_BYTE

  for(::uint32_t i = 0; i < header.NumberOfRvaAndSizes; i++) {
    ::uint32_t  c = (i*sizeof(data_directory));
    c+= _offset(optional_header_32, DataDirectory[0]);
    ::uint32_t  o; 

    o = c + _offset(data_directory, VirtualAddress);
    if(readDword(b, o, header.DataDirectory[i].VirtualAddress) == false) {
      return false;
    }

    o = c + _offset(data_directory, Size);
    if(readDword(b, o, header.DataDirectory[i].Size) == false) {
      return false;
    }
  }

  return true;
}

bool readFileHeader(bounded_buffer *b, file_header &header) {
#define READ_WORD(x) \
  if(readWord(b, _offset(file_header, x), header.x) == false) { \
    return false; \
  } 
#define READ_DWORD(x) \
  if(readDword(b, _offset(file_header, x), header.x) == false) { \
    return false; \
  } 

  READ_WORD(Machine);
  READ_WORD(NumberOfSections);
  READ_DWORD(TimeDateStamp);
  READ_DWORD(PointerToSymbolTable);
  READ_DWORD(NumberOfSymbols);
  READ_WORD(SizeOfOptionalHeader);
  READ_WORD(Characteristics);

#undef READ_DWORD
#undef READ_WORD
  return true;
}

bool readNtHeader(bounded_buffer *b, nt_header_32 &header) {
  if(b == NULL) {
    return false;
  }

  ::uint32_t  pe_magic;
  ::uint32_t  curOffset =0;
  if(readDword(b, curOffset, pe_magic) == false || pe_magic != NT_MAGIC) {
    return false;
  }

  header.Signature = pe_magic;
  bounded_buffer  *fhb = 
    splitBuffer(b, _offset(nt_header_32, FileHeader), b->bufLen);
  
  if(fhb == NULL) {
    return false;
  }

  if(readFileHeader(fhb, header.FileHeader) == false) {
    deleteBuffer(fhb);
    return false;
  }

  bounded_buffer *ohb = 
    splitBuffer(b, _offset(nt_header_32, OptionalHeader), b->bufLen);

  if(ohb == NULL) {
    deleteBuffer(fhb);
    return false;
  }

  if(readOptionalHeader(ohb, header.OptionalHeader) == false) {
    deleteBuffer(ohb);
    deleteBuffer(fhb);
    return false;
  }

  deleteBuffer(ohb);
  deleteBuffer(fhb);

  return true;
}

bool getHeader(bounded_buffer *file, pe_header &p, bounded_buffer *&rem) {
  if(file == NULL) {
    return false;
  }

  //start by reading MZ
  ::uint16_t  tmp = 0;
  ::uint32_t  curOffset = 0;
  if(readWord(file, curOffset, tmp) == false) {
    return false;
  }
  if(tmp != MZ_MAGIC) {
    return false;
  }

  //read the offset to the NT headers
  ::uint32_t  offset;
  if(readDword(file, _offset(dos_header, e_lfanew), offset) == false) {
    return false;
  }
  curOffset += offset; 

  //now, we can read out the fields of the NT headers
  bounded_buffer  *ntBuf = splitBuffer(file, curOffset, file->bufLen);
  if(readNtHeader(ntBuf, p.nt) == false) {
    return false;
  }

  //update 'rem' to point to the space after the header
  rem = splitBuffer(ntBuf, sizeof(nt_header_32), ntBuf->bufLen);
  deleteBuffer(ntBuf);

  return true;
}

parsed_pe *ParsePEFromFile(const char *filePath) {
  //first, create a new parsed_pe structure
  parsed_pe *p = new parsed_pe();

  if(p == NULL) {
    return NULL;
  }

  //make a new buffer object to hold just our file data 
  p->fileBuffer = readFileToFileBuffer(filePath);

  if(p->fileBuffer == NULL) {
    delete p;
    return NULL;
  }

  p->internal = new parsed_pe_internal();

  if(p->internal == NULL) {
    deleteBuffer(p->fileBuffer);
    delete p;
    return NULL;
  }

  //get header information
  bounded_buffer  *remaining = NULL;
  if(getHeader(p->fileBuffer, p->peHeader, remaining) == false) {
    deleteBuffer(p->fileBuffer);
    delete p;
    return NULL;
  }

  bounded_buffer  *file = p->fileBuffer;
  if(getSections(remaining, file, p->peHeader.nt, p->internal->secs) == false) {
    deleteBuffer(remaining);
    deleteBuffer(p->fileBuffer);
    delete p;
    return NULL;
  }

  //get exports
  data_directory  exportDir = 
    p->peHeader.nt.OptionalHeader.DataDirectory[DIR_EXPORT];
  if(exportDir.Size != 0) {
    section s;
    ::uint32_t  addr = 
      exportDir.VirtualAddress + p->peHeader.nt.OptionalHeader.ImageBase;

    if(getSecForVA(p->internal->secs, addr, s) == false) {
      return NULL;
    }

    ::uint32_t  rvaofft = addr - s.sectionBase;

    //get the name of this module
    ::uint32_t  nameRva;
    if(readDword( s.sectionData,
                  rvaofft+_offset(export_dir_table, NameRVA),
                  nameRva) == false) 
    {
      return NULL;
    }

    ::uint32_t  nameVA = nameRva + p->peHeader.nt.OptionalHeader.ImageBase;

    section nameSec;
    if(getSecForVA(p->internal->secs, nameVA, nameSec) == false) {
      return NULL;
    }

    ::uint32_t  nameOff = nameVA - nameSec.sectionBase;
    string      modName;
    ::uint8_t   c;
    do {
      if(readByte(nameSec.sectionData, nameOff, c) == false) {
        return NULL;
      }
      
      if(c == 0) {
        break;
      }

      modName.push_back(c);
      nameOff++;
    }while(true);

    //now, get all the named export symbols
    ::uint32_t  numNames;
    if(readDword( s.sectionData,
                  rvaofft+_offset(export_dir_table, NumberOfNamePointers),
                  numNames) == false)
    {
      return NULL;
    }

    if(numNames > 0) {
      //get the names section
      ::uint32_t  namesRVA;
      if(readDword( s.sectionData,
                    rvaofft+_offset(export_dir_table, NamePointerRVA),
                    namesRVA) == false) 
      {
        return NULL;
      }

      ::uint32_t  namesVA = 
        namesRVA + p->peHeader.nt.OptionalHeader.ImageBase;
      section     namesSec;

      if(getSecForVA(p->internal->secs, namesVA, namesSec) == false) {
        return NULL;
      }

      ::uint32_t  namesOff = namesVA - namesSec.sectionBase;

      //get the EAT section
      ::uint32_t  eatRVA;
      if(readDword( s.sectionData,
                    rvaofft+_offset(export_dir_table, ExportAddressTableRVA),
                    eatRVA) == false)
      {
        return NULL;
      }

      ::uint32_t  eatVA = 
        eatRVA + p->peHeader.nt.OptionalHeader.ImageBase;
      section     eatSec;
      if(getSecForVA(p->internal->secs, eatVA, eatSec) == false) {
        return NULL;
      }

      ::uint32_t  eatOff = eatVA - eatSec.sectionBase;

      //get the ordinal base 
      ::uint32_t  ordinalBase;
      if(readDword( s.sectionData,
                    rvaofft+_offset(export_dir_table, OrdinalBase),
                    ordinalBase) == false)
      {
        return NULL;
      }

      //get the ordinal table
      ::uint32_t  ordinalTableRVA;
      if(readDword( s.sectionData,
                    rvaofft+_offset(export_dir_table, OrdinalTableRVA),
                    ordinalTableRVA) == false)

      {
        return NULL;
      }

      ::uint32_t  ordinalTableVA = 
        ordinalTableRVA + p->peHeader.nt.OptionalHeader.ImageBase;
      section     ordinalTableSec;
      if(getSecForVA(p->internal->secs, ordinalTableVA, ordinalTableSec) == false) {
        return NULL;
      }

      ::uint32_t  ordinalOff = ordinalTableVA - ordinalTableSec.sectionBase;

      for(::uint32_t  i = 0; i < numNames; i++) {
        ::uint32_t  curNameRVA;
        if(readDword( namesSec.sectionData,
                      namesOff+(i*sizeof(::uint32_t)),
                      curNameRVA) == false)
        {
          return NULL;
        }
 
        ::uint32_t  curNameVA = 
          curNameRVA + p->peHeader.nt.OptionalHeader.ImageBase;
        section     curNameSec;

        if(getSecForVA(p->internal->secs, curNameVA, curNameSec) == false) {
          return NULL;
        }

        ::uint32_t  curNameOff = curNameVA - curNameSec.sectionBase;
        string      symName;
        ::uint8_t   d;

        do {
          if(readByte(curNameSec.sectionData, curNameOff, d) == false) {
            return NULL;
          }

          if(d == 0) {
            break;
          }

          symName.push_back(d);
          curNameOff++;
        }while(true);

        //now, for this i, look it up in the ExportOrdinalTable
        ::uint16_t  ordinal;
        if(readWord(ordinalTableSec.sectionData, 
                    ordinalOff+(i*sizeof(uint16_t)), 
                    ordinal) == false) 
        {
          return NULL;
        }

        //::uint32_t  eatIdx = ordinal - ordinalBase;
        ::uint32_t  eatIdx = (ordinal*sizeof(uint32_t));

        ::uint32_t  symRVA;
        if(readDword(eatSec.sectionData, eatOff+eatIdx, symRVA) == false) {
          return NULL;
        }

        bool  isForwarded = 
          ((symRVA >= exportDir.VirtualAddress) && 
          (symRVA < exportDir.VirtualAddress+exportDir.Size));
        
        if(isForwarded == false) {
          ::uint32_t  symVA = symRVA + p->peHeader.nt.OptionalHeader.ImageBase;
          exportent a;

          a.addr = symVA;
          a.symbolName = symName;
          a.moduleName = modName;
          p->internal->exports.push_back(a);
        }
      }
    }
  }

  //get relocations, if exist
  data_directory  relocDir = 
    p->peHeader.nt.OptionalHeader.DataDirectory[DIR_BASERELOC];
  if(relocDir.Size != 0) {
    section d;
    ::uint32_t  vaAddr = 
      relocDir.VirtualAddress + p->peHeader.nt.OptionalHeader.ImageBase;

    if(getSecForVA(p->internal->secs, vaAddr, d) == false) {
      deleteBuffer(remaining);
      deleteBuffer(p->fileBuffer);
      delete p;
      return NULL;
    }

    ::uint32_t secExtentVA = d.sectionBase + bufLen(d.sectionData);

    //loop through relocation entries
    while(vaAddr < secExtentVA) {
        ::uint32_t  rvaofft = vaAddr - d.sectionBase;
        ::uint32_t  pageRva;
        ::uint32_t  blockSize;

        if(readDword( d.sectionData, 
                    rvaofft+_offset(reloc_block, PageRVA), 
                    pageRva) == false)
        {
            return NULL;
        }

        if(readDword( d.sectionData, 
                    rvaofft+_offset(reloc_block, BlockSize), 
                    blockSize) == false)
        {
            return NULL;
        }

        // we are done early
        if(pageRva == 0 && blockSize == 0) {
            break;
        }

        // blockSize is inclusive of the RVA DWORD and the 
        // blockSize DWORD. Anything <8 is invalid
        if(blockSize < 8) {
            return NULL;
        }

        //iter over all of the blocks
        ::uint32_t  blockCount = (blockSize-8)/sizeof(::uint16_t);

        rvaofft += sizeof(reloc_block);

        while(blockCount != 0) {
            ::uint16_t  block;
            ::uint8_t   type;
            ::uint16_t  offset;

            if(readWord(d.sectionData, rvaofft, block) == false) {
                return NULL;
            }

            // skip padding null blocks sometimes emitted by msvc
            if(block != 0x0) {

                //mask out the type and assign
                type = block >> 12;
                //mask out the offset and assign
                offset = block & ~0xf000;

                //produce the VA of the relocation
                ::uint32_t  relocVA = pageRva + offset + 
                    p->peHeader.nt.OptionalHeader.ImageBase;

                //store in our list
                reloc r;

                r.shiftedAddr = relocVA;
                r.type = (reloc_type)type;
                p->internal->relocs.push_back(r);
            }

            blockCount--;
            rvaofft += sizeof(::uint16_t);
        }
        vaAddr = rvaofft + d.sectionBase;
    }

  }
   
  //get imports
  data_directory  importDir = 
    p->peHeader.nt.OptionalHeader.DataDirectory[DIR_IMPORT];
  if(importDir.Size != 0) {
    //get section for the RVA in importDir
    section c;
    ::uint32_t  addr = 
      importDir.VirtualAddress + p->peHeader.nt.OptionalHeader.ImageBase;

    if(getSecForVA(p->internal->secs, addr, c) == false) {
      deleteBuffer(remaining);
      deleteBuffer(p->fileBuffer);
      delete p;
      return NULL;
    }

    //get import directory from this section
    ::uint32_t  offt = addr - c.sectionBase;
    do {
#define READ_DWORD(x) \
    if(readDword(c.sectionData, offt+_offset(import_dir_entry, x), curEnt.x) == false) { \
      return NULL; \
    }
      //read each directory entry out
      import_dir_entry  curEnt;

      READ_DWORD(LookupTableRVA);
      READ_DWORD(TimeStamp);
      READ_DWORD(ForwarderChain);
      READ_DWORD(NameRVA);
      READ_DWORD(AddressRVA);

      //are all the fields in curEnt null? then we break
      if( curEnt.LookupTableRVA == 0 && 
          curEnt.NameRVA == 0 &&
          curEnt.AddressRVA == 0) {
        break;
      }

      //then, try and get the name of this particular module...
      ::uint32_t  name = 
        curEnt.NameRVA + p->peHeader.nt.OptionalHeader.ImageBase;

      section nameSec;
      if(getSecForVA(p->internal->secs, name, nameSec) == false) {
        return NULL;
      }

      ::uint32_t  nameOff = name - nameSec.sectionBase;
      string      modName;
      ::uint8_t   c;
      do {
        if(readByte(nameSec.sectionData, nameOff, c) == false) {
          return NULL;
        }
        
        if(c == 0) {
          break;
        }

        modName.push_back(toupper(c));
        nameOff++;
      }while(true);

      //then, try and get all of the sub-symbols
      ::uint32_t  lookupVA;
      if(curEnt.LookupTableRVA != 0) { 
      lookupVA = 
        curEnt.LookupTableRVA + p->peHeader.nt.OptionalHeader.ImageBase;
      } else if(curEnt.AddressRVA != 0 ) {
      lookupVA = 
        curEnt.AddressRVA + p->peHeader.nt.OptionalHeader.ImageBase;
      }

      section lookupSec;
      if(getSecForVA(p->internal->secs, lookupVA, lookupSec) == false) {
        return NULL;
      }
      
      ::uint32_t  lookupOff = lookupVA - lookupSec.sectionBase;
      ::uint32_t  offInTable = 0;
      do {
        ::uint32_t  val;
        if(readDword(lookupSec.sectionData, lookupOff, val) == false) {
          return NULL;
        }

        if(val == 0) {
          break;
        }

        //check and see if high bit is set
        if(val >> 31 == 0) {
          //import by name
          string  symName;
          section symNameSec;
          ::uint32_t  valVA = val + p->peHeader.nt.OptionalHeader.ImageBase;
          if(getSecForVA(p->internal->secs, valVA, symNameSec) == false) {
            return NULL;
          }
          
          ::uint32_t  nameOff = valVA - symNameSec.sectionBase;
          nameOff += sizeof(::uint16_t);
          do {
            ::uint8_t d;

            if(readByte(symNameSec.sectionData, nameOff, d) == false) {
              return NULL;
            }
            
            if(d == 0) {
              break;
            }

            symName.push_back(d);
            nameOff++;
          } while(true);

          //okay now we know the pair... add it
          importent ent;

          ent.addr = offInTable + 
            curEnt.AddressRVA + p->peHeader.nt.OptionalHeader.ImageBase;

          ent.symbolName = symName;
          ent.moduleName = modName;
          p->internal->imports.push_back(ent);
        } else {
          //import by ordinal
          //mask out 'val' so that oval is the low 16 bits of 'val'
          ::uint16_t  oval = (val & ~0xFFFF0000);
          string      symName = 
            "ORDINAL_" + modName + "_" + to_string<uint32_t>(oval, dec);
          
          importent ent;

          ent.addr = offInTable + 
            curEnt.AddressRVA + p->peHeader.nt.OptionalHeader.ImageBase;
          
          ent.symbolName = symName;
          ent.moduleName = modName;

          p->internal->imports.push_back(ent);
        }
        
        lookupOff += sizeof(::uint32_t);
        offInTable += sizeof(::uint32_t);
      } while(true);

      offt += sizeof(import_dir_entry);
    } while(true);
  }

  deleteBuffer(remaining);

#undef READ_DWORD
  return p;
}

void DestructParsedPE(parsed_pe *p) {

  delete p;
  return;
}

//iterate over the imports by VA and string
void IterImpVAString(parsed_pe *pe, iterVAStr cb, void *cbd) {
  list<importent> &l = pe->internal->imports;

  for(list<importent>::iterator it = l.begin(), e = l.end(); it != e; ++it) {
    importent i = *it;
    if(cb(cbd, i.addr, i.moduleName, i.symbolName) != 0) {
      break;
    }
  }

  return;
}

//iterate over relocations in the PE file
void IterRelocs(parsed_pe *pe, iterReloc cb, void *cbd) {
  list<reloc> &l = pe->internal->relocs;

  for(list<reloc>::iterator it = l.begin(), e = l.end(); it != e; ++it) {
    reloc r = *it;
    if(cb(cbd, r.shiftedAddr, r.type) != 0) {
      break;
    }
  }

  return;
}

//iterate over the exports by VA
void IterExpVA(parsed_pe *pe, iterExp cb, void *cbd) {
  list<exportent> &l = pe->internal->exports;

  for(list<exportent>::iterator it = l.begin(), e = l.end(); it != e; ++it) {
    exportent i = *it;

    if(cb(cbd, i.addr, i.moduleName, i.symbolName)) {
      break;
    }
  }

  return;
}

//iterate over sections
void IterSec(parsed_pe *pe, iterSec cb, void *cbd) {
  parsed_pe_internal  *pint = pe->internal;

  for(list<section>::iterator sit = pint->secs.begin(), e = pint->secs.end();
      sit != e;
      ++sit)
  {
    section s = *sit;
    if(cb(cbd, s.sectionBase, s.sectionName, s.sec, s.sectionData) != 0) {
      break;
    }
  }

  return;
}

bool ReadByteAtVA(parsed_pe *pe, VA v, ::uint8_t &b) {
  //find this VA in a section
  section s;

  if(getSecForVA(pe->internal->secs, v, s) == false) {
    return false;
  }

  ::uint32_t  off = v - s.sectionBase;

  return readByte(s.sectionData, off, b);
}

bool GetEntryPoint(const parsed_pe *pe, VA &v) {

  if(pe != NULL) {
    const nt_header_32  *nthdr = &pe->peHeader.nt;

    v = nthdr->OptionalHeader.AddressOfEntryPoint + nthdr->OptionalHeader.ImageBase;

    return true;
  }

  return false;
}
