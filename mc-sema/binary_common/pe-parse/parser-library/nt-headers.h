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

#ifndef _NT_HEADERS
#define _NT_HEADERS
#include <boost/cstdint.hpp>

#define _offset(t, f) ((boost::uint32_t)(ptrdiff_t)&(((t*)0)->f))

//need to pack these structure definitions

//some constant definitions
const boost::uint16_t MZ_MAGIC = 0x5A4D;
const boost::uint32_t NT_MAGIC = 0x00004550;
const boost::uint16_t NUM_DIR_ENTRIES = 16;
const boost::uint16_t NT_OPTIONAL_32_MAGIC = 0x10B;
const boost::uint16_t NT_SHORT_NAME_LEN = 8;
const boost::uint16_t DIR_EXPORT = 0;
const boost::uint16_t DIR_IMPORT = 1;
const boost::uint16_t DIR_RESOURCE = 2;
const boost::uint16_t DIR_EXCEPTION = 3;
const boost::uint16_t DIR_SECURITY = 4;
const boost::uint16_t DIR_BASERELOC = 5;
const boost::uint16_t DIR_DEBUG = 6;
const boost::uint16_t DIR_ARCHITECTURE = 7;
const boost::uint16_t DIR_GLOBALPTR = 8;
const boost::uint16_t DIR_TLS = 9;
const boost::uint16_t DIR_LOAD_CONFIG = 10;
const boost::uint16_t DIR_BOUND_IMPORT = 11;
const boost::uint16_t DIR_IAT = 12;
const boost::uint16_t DIR_DELAY_IMPORT = 13;
const boost::uint16_t DIR_COM_DESCRIPTOR = 14;

const boost::uint32_t IMAGE_SCN_TYPE_NO_PAD = 0x00000008;
const boost::uint32_t IMAGE_SCN_CNT_CODE = 0x00000020;
const boost::uint32_t IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040; 
const boost::uint32_t IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
const boost::uint32_t IMAGE_SCN_LNK_OTHER = 0x00000100;
const boost::uint32_t IMAGE_SCN_LNK_INFO = 0x00000200;
const boost::uint32_t IMAGE_SCN_LNK_REMOVE = 0x00000800;
const boost::uint32_t IMAGE_SCN_LNK_COMDAT = 0x00001000;
const boost::uint32_t IMAGE_SCN_NO_DEFER_SPEC_EXC = 0x00004000;
const boost::uint32_t IMAGE_SCN_GPREL = 0x00008000;
const boost::uint32_t IMAGE_SCN_MEM_FARDATA = 0x00008000;
const boost::uint32_t IMAGE_SCN_MEM_PURGEABLE = 0x00020000;
const boost::uint32_t IMAGE_SCN_MEM_16BIT = 0x00020000;
const boost::uint32_t IMAGE_SCN_MEM_LOCKED = 0x00040000;
const boost::uint32_t IMAGE_SCN_MEM_PRELOAD = 0x00080000;
const boost::uint32_t IMAGE_SCN_ALIGN_1BYTES = 0x00100000;
const boost::uint32_t IMAGE_SCN_ALIGN_2BYTES = 0x00200000;
const boost::uint32_t IMAGE_SCN_ALIGN_4BYTES = 0x00300000;
const boost::uint32_t IMAGE_SCN_ALIGN_8BYTES = 0x00400000;
const boost::uint32_t IMAGE_SCN_ALIGN_16BYTES = 0x00500000;
const boost::uint32_t IMAGE_SCN_ALIGN_32BYTES = 0x00600000;
const boost::uint32_t IMAGE_SCN_ALIGN_64BYTES = 0x00700000;
const boost::uint32_t IMAGE_SCN_ALIGN_128BYTES = 0x00800000;
const boost::uint32_t IMAGE_SCN_ALIGN_256BYTES = 0x00900000;
const boost::uint32_t IMAGE_SCN_ALIGN_512BYTES = 0x00A00000;
const boost::uint32_t IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000;
const boost::uint32_t IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000;
const boost::uint32_t IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000;
const boost::uint32_t IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000;
const boost::uint32_t IMAGE_SCN_ALIGN_MASK = 0x00F00000;
const boost::uint32_t IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000;
const boost::uint32_t IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
const boost::uint32_t IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
const boost::uint32_t IMAGE_SCN_MEM_NOT_PAGED = 0x08000000;
const boost::uint32_t IMAGE_SCN_MEM_SHARED = 0x10000000;
const boost::uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
const boost::uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
const boost::uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;

struct dos_header {
    boost::uint16_t   e_magic;           
    boost::uint16_t   e_cblp;            
    boost::uint16_t   e_cp;              
    boost::uint16_t   e_crlc;            
    boost::uint16_t   e_cparhdr;         
    boost::uint16_t   e_minalloc;        
    boost::uint16_t   e_maxalloc;        
    boost::uint16_t   e_ss;              
    boost::uint16_t   e_sp;              
    boost::uint16_t   e_csum;            
    boost::uint16_t   e_ip;              
    boost::uint16_t   e_cs;              
    boost::uint16_t   e_lfarlc; 
    boost::uint16_t   e_ovno;            
    boost::uint16_t   e_res[4];          
    boost::uint16_t   e_oemid;           
    boost::uint16_t   e_oeminfo; 
    boost::uint16_t   e_res2[10];        
    boost::uint32_t   e_lfanew;          
};

struct file_header {
    boost::uint16_t   Machine;
    boost::uint16_t   NumberOfSections;
    boost::uint32_t   TimeDateStamp;
    boost::uint32_t   PointerToSymbolTable;
    boost::uint32_t   NumberOfSymbols;
    boost::uint16_t   SizeOfOptionalHeader;
    boost::uint16_t   Characteristics;
};

struct data_directory {
  boost::uint32_t VirtualAddress;
  boost::uint32_t Size;
};

struct optional_header_32 {
  boost::uint16_t   Magic;
  boost::uint8_t    MajorLinkerVersion;
  boost::uint8_t    MinorLinkerVersion;
  boost::uint32_t   SizeOfCode;
  boost::uint32_t   SizeOfInitializedData;
  boost::uint32_t   SizeOfUninitializedData;
  boost::uint32_t   AddressOfEntryPoint;
  boost::uint32_t   BaseOfCode;
  boost::uint32_t   BaseOfData;
  boost::uint32_t   ImageBase;
  boost::uint32_t   SectionAlignment;
  boost::uint32_t   FileAlignment;
  boost::uint16_t   MajorOperatingSystemVersion;
  boost::uint16_t   MinorOperatingSystemVersion;
  boost::uint16_t   MajorImageVersion;
  boost::uint16_t   MinorImageVersion;
  boost::uint16_t   MajorSubsystemVersion;
  boost::uint16_t   MinorSubsystemVersion;
  boost::uint32_t   Win32VersionValue;
  boost::uint32_t   SizeOfImage;
  boost::uint32_t   SizeOfHeaders;
  boost::uint32_t   CheckSum;
  boost::uint16_t   Subsystem;
  boost::uint16_t   DllCharacteristics;
  boost::uint32_t   SizeOfStackReserve;
  boost::uint32_t   SizeOfStackCommit;
  boost::uint32_t   SizeOfHeapReserve;
  boost::uint32_t   SizeOfHeapCommit;
  boost::uint32_t   LoaderFlags;
  boost::uint32_t   NumberOfRvaAndSizes;
  data_directory    DataDirectory[NUM_DIR_ENTRIES];
};

struct nt_header_32 {
  boost::uint32_t     Signature;
  file_header         FileHeader;
  optional_header_32  OptionalHeader;
};

struct image_section_header {
    boost::uint8_t    Name[NT_SHORT_NAME_LEN];
    union {
            boost::uint32_t   PhysicalAddress;
            boost::uint32_t   VirtualSize;
    } Misc;
    boost::uint32_t   VirtualAddress;
    boost::uint32_t   SizeOfRawData;
    boost::uint32_t   PointerToRawData;
    boost::uint32_t   PointerToRelocations;
    boost::uint32_t   PointerToLinenumbers;
    boost::uint16_t   NumberOfRelocations;
    boost::uint16_t   NumberOfLinenumbers;
    boost::uint32_t   Characteristics;
};

struct import_dir_entry {
  boost::uint32_t LookupTableRVA;
  boost::uint32_t TimeStamp;
  boost::uint32_t ForwarderChain;
  boost::uint32_t NameRVA;
  boost::uint32_t AddressRVA;
};

struct export_dir_table {
  boost::uint32_t ExportFlags;
  boost::uint32_t TimeDateStamp;
  boost::uint16_t MajorVersion;
  boost::uint16_t MinorVersion;
  boost::uint32_t NameRVA;
  boost::uint32_t OrdinalBase;
  boost::uint32_t AddressTableEntries;
  boost::uint32_t NumberOfNamePointers;
  boost::uint32_t ExportAddressTableRVA;
  boost::uint32_t NamePointerRVA;
  boost::uint32_t OrdinalTableRVA;
};

enum reloc_type {
  ABSOLUTE = 0,
  HIGH = 1,
  LOW = 2,
  HIGHLOW = 3,
  HIGHADJ = 4,
  MIPS_JMPADDR = 5,
  MIPS_JMPADDR16 = 9,
  IA64_IMM64 = 9,
  DIR64 = 10
};

struct reloc_block {
  boost::uint32_t PageRVA;
  boost::uint32_t BlockSize;
};

#endif
