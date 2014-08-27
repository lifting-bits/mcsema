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
#include "raiseX86.h"
#include "InstructionDispatch.h"

void MOV_populateDispatchMap(DispatchMap &m);

template <int width>
InstTransResult doMRMov(InstPtr ip, llvm::BasicBlock *&b,
                        llvm::Value           *dstAddr,
                        const llvm::MCOperand &src)
{
    //MOV <mem>, <r>
    TASSERT(src.isReg(), "src is not a register");
    TASSERT(dstAddr != NULL, "Destination addr can't be null");

    M_WRITE<width>(ip, b, dstAddr, R_READ<width>(b, src.getReg()));

    return ContinueBlock;
}


template <int width>
InstTransResult doRRMov(InstPtr ip, llvm::BasicBlock *b, 
                        const llvm::MCOperand &dst, 
                        const llvm::MCOperand &src) 
{
    //MOV <r>, <r>
    TASSERT(src.isReg(), "");
    TASSERT(dst.isReg(), "");
    
    //pretty straightforward

    R_WRITE<width>(b, dst.getReg(), R_READ<width>(b, src.getReg()));
        
    return ContinueBlock;
}

template <int width>
InstTransResult doRMMov(InstPtr ip, llvm::BasicBlock      *b,
                        llvm::Value           *srcAddr,
                        const llvm::MCOperand &dst)
{
    //MOV <r>, <mem>
    TASSERT(dst.isReg(), "");
    TASSERT(srcAddr != NULL, "");

    R_WRITE<width>(b, dst.getReg(), M_READ<width>(ip, b, srcAddr));

    return ContinueBlock;
}

template <int width>
llvm::Value *getValueForExternal(llvm::Module *M, InstPtr ip, llvm::BasicBlock *block) {

    llvm::Value *addrInt = NULL;

    if( ip->has_ext_call_target() ) {
        if (width != 32) {
            throw TErr(__LINE__, __FILE__, "NIY: non 32-bit width for external calls");
        }
        std::string target = ip->get_ext_call_target()->getSymbolName();
        llvm::Value *ext_fn = M->getFunction(target);
        TASSERT(ext_fn != NULL, "Could not find external: " + target);
        llvm::Value *addrInt = new llvm::PtrToIntInst(
                ext_fn, llvm::Type::getInt32Ty(block->getContext()), "", block);

        return addrInt;
    } else if (ip->has_ext_data_ref() ) {
        std::string target = ip->get_ext_data_ref()->getSymbolName();
        llvm::Value *gvar = M->getGlobalVariable(target);

        TASSERT(gvar != NULL, "Could not find external data: " + target);

        
        if(gvar->getType()->isPointerTy()) {
            addrInt = new llvm::PtrToIntInst(
                    gvar, llvm::Type::getIntNTy(block->getContext(), width), "", block);
        } else {

            llvm::IntegerType *int_t = llvm::dyn_cast<llvm::IntegerType>(gvar->getType());
            if( int_t == NULL) {
                throw TErr(__LINE__, __FILE__, "NIY: non-integer external data");
            }
            else if(int_t->getBitWidth() < width) {
                addrInt = new llvm::ZExtInst(gvar, 
                        llvm::Type::getIntNTy(block->getContext(), width),
                        "",
                        block);
            }
            else if(int_t->getBitWidth() == width) {
                addrInt = gvar;
            }
            else {
                throw TErr(__LINE__, __FILE__, "NIY: external type > width");
            }
        }

    } else {
        throw TErr(__LINE__, __FILE__, "No external refernce to get value for!");
    }

    return addrInt;

}

