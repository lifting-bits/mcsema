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

#include <iostream>
#include <sstream>
#include "parse.h"

using namespace std;
using namespace boost;

template <class T>
static
string to_string(T t, ios_base & (*f)(ios_base&)) {
    ostringstream oss;
    oss << f << t;
    return oss.str();
}

int printExps(void *N, VA funcAddr, std::string &mod, std::string &func) {
  cout << "EXP: ";
  cout << mod;
  cout << "!";
  cout << func;
  cout << ":";
  cout << to_string<uint32_t>(funcAddr, hex);
  cout << endl;
  return 0;
}

int printImports(void *N, VA impAddr, string &modName, string &symName) {
  cout << "0x" << to_string<uint32_t>(impAddr, hex);
  cout << " " << modName << "!" << symName;
  cout << endl;
  return 0;
}

int printRelocs(void *N, VA relocAddr, reloc_type type) {
  cout << "TYPE: ";
  switch(type) {
    case ABSOLUTE:
      cout << "ABSOLUTE";
      break;
    case HIGH:
      cout << "HIGH";
      break;
    case LOW:
      cout << "LOW";
      break;
    case HIGHLOW:
      cout << "HIGHLOW";
      break;
    case HIGHADJ:
      cout << "HIGHADJ";
      break;
    case MIPS_JMPADDR:
      cout << "MIPS_JMPADDR";
      break;
    case MIPS_JMPADDR16:
      cout << "MIPS_JMPADD16";
      break;
    case DIR64:
      cout << "DIR64";
      break;
  }

  cout << " VA: 0x" << to_string<VA>(relocAddr, hex) << endl;

  return 0 ;
}

int printSecs(void                  *N, 
              VA                    secBase, 
              string                &secName, 
              image_section_header  s,
              bounded_buffer        *data) 
{
  cout << "Sec Name: " << secName << endl;
  cout << "Sec Base: " << to_string<VA>(secBase, hex) << endl;
  cout << "Sec Size: " << to_string<VA>(data->bufLen, dec) << endl;
  return 0;
}

int main(int argc, char *argv[]) {
  if(argc == 2) {
    parsed_pe *p = ParsePEFromFile(argv[1]);

    if(p != NULL) {
      //print out some things
#define DUMP_FIELD(x) \
      cout << "" #x << ": 0x"; \
      cout << to_string<uint32_t>(p->peHeader.x, hex) << endl;
#define DUMP_DEC_FIELD(x) \
      cout << "" #x << ": "; \
      cout << to_string<uint32_t>(p->peHeader.x, dec) << endl;

      DUMP_FIELD(nt.Signature);
      DUMP_FIELD(nt.FileHeader.Machine);
      DUMP_FIELD(nt.FileHeader.NumberOfSections);
      DUMP_DEC_FIELD(nt.FileHeader.TimeDateStamp);
      DUMP_FIELD(nt.FileHeader.PointerToSymbolTable);
      DUMP_DEC_FIELD(nt.FileHeader.NumberOfSymbols);
      DUMP_FIELD(nt.FileHeader.SizeOfOptionalHeader);
      DUMP_FIELD(nt.FileHeader.Characteristics);
      DUMP_FIELD(nt.OptionalHeader.Magic);
      DUMP_DEC_FIELD(nt.OptionalHeader.MajorLinkerVersion);
      DUMP_DEC_FIELD(nt.OptionalHeader.MinorLinkerVersion);
      DUMP_FIELD(nt.OptionalHeader.SizeOfCode);
      DUMP_FIELD(nt.OptionalHeader.SizeOfInitializedData);
      DUMP_FIELD(nt.OptionalHeader.SizeOfUninitializedData);
      DUMP_FIELD(nt.OptionalHeader.AddressOfEntryPoint);
      DUMP_FIELD(nt.OptionalHeader.BaseOfCode);
      DUMP_FIELD(nt.OptionalHeader.BaseOfData);
      DUMP_FIELD(nt.OptionalHeader.ImageBase);
      DUMP_FIELD(nt.OptionalHeader.SectionAlignment);
      DUMP_FIELD(nt.OptionalHeader.FileAlignment);
      DUMP_DEC_FIELD(nt.OptionalHeader.MajorOperatingSystemVersion);
      DUMP_DEC_FIELD(nt.OptionalHeader.MinorOperatingSystemVersion);
      DUMP_DEC_FIELD(nt.OptionalHeader.Win32VersionValue);
      DUMP_FIELD(nt.OptionalHeader.SizeOfImage);
      DUMP_FIELD(nt.OptionalHeader.SizeOfHeaders);
      DUMP_FIELD(nt.OptionalHeader.CheckSum);
      DUMP_FIELD(nt.OptionalHeader.Subsystem);
      DUMP_FIELD(nt.OptionalHeader.DllCharacteristics);
      DUMP_FIELD(nt.OptionalHeader.SizeOfStackReserve);
      DUMP_FIELD(nt.OptionalHeader.SizeOfStackCommit);
      DUMP_FIELD(nt.OptionalHeader.SizeOfHeapReserve);
      DUMP_FIELD(nt.OptionalHeader.SizeOfHeapCommit);
      DUMP_FIELD(nt.OptionalHeader.LoaderFlags);
      DUMP_DEC_FIELD(nt.OptionalHeader.NumberOfRvaAndSizes);

#undef DUMP_FIELD
#undef DUMP_DEC_FIELD

      cout << "Imports: " << endl;
      IterImpVAString(p, printImports, NULL);
      cout << "Relocations: " << endl;
      IterRelocs(p, printRelocs, NULL);
      cout << "Sections: " << endl;
      IterSec(p, printSecs, NULL);
      cout << "Exports: " << endl;
      IterExpVA(p, printExps, NULL);

      //read the first 8 bytes from the entry point and print them
      VA  entryPoint;
      if(GetEntryPoint(p, entryPoint)) {
        cout << "First 8 bytes from entry point (0x";
        
        cout << to_string<VA>(entryPoint, hex);
        cout << "):" << endl;
        for(int i = 0; i < 8; i++) {
          ::uint8_t b;
          ReadByteAtVA(p, i+entryPoint, b);
          cout << " 0x" << to_string<uint32_t>(b, hex);
        }

        cout << endl;
      }

      DestructParsedPE(p);
    }
  }
  return 0;
}
