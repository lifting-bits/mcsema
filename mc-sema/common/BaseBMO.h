//===-- .h ---------------------------------------------------===//
//
//                      THE PROJECT
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//
//===----------------------------------------------------------------------===//

#ifndef _BMO_H
#define _BMO_H
#include "llvm/Support/MemoryBuffer.h"
#include <boost/cstdint.hpp>

class BaseBufferMemoryObject : public llvm::MemoryObject {
private:
    std::vector<uint8_t>  Bytes;
    uint64_t              Base;
public:
    BaseBufferMemoryObject( std::vector<uint8_t>  bytes,
                            uint64_t              baseAddr) :
                            Bytes(bytes), Base(baseAddr) {
        return;
    }

    uint64_t getBase() const { return this->Base; }
    uint64_t getExtent() const { return this->Bytes.size()+this->Base; }

    int readByte(uint64_t addr, uint8_t *byte) const {
        if (addr >= this->getBase() )
        {
          if(addr < this->getExtent())
          {
            *byte = this->Bytes[addr-this->Base];
            return 0;
          }
          else
          {
              return -1;
          }
        }
        else
        {
          return -1;
        }
    }
};

#endif
