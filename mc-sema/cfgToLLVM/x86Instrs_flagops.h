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
#pragma once
#include "raiseX86.h"
#include <vector>

using namespace llvm;
using namespace std;

template <int width>
static void WriteZF(BasicBlock *b, Value *w) {
    //set ZF
    //ZF is set if the result is 0 and clear otherwise
    F_WRITE(b, ZF, new ICmpInst(*b, CmpInst::ICMP_EQ, w, CONST_V<width>(b, 0)));
    return;
}

template <int width>
static void WriteCF(BasicBlock *b) {

    return;
}

template <int width>
static void WriteCFShiftR(BasicBlock *b, Value *val, Value *shiftAmt) {
    
    Value   *v = 
        BinaryOperator::CreateLShr(val, 
            BinaryOperator::CreateSub(shiftAmt, CONST_V<width>(b, 1), "", b), "", b);
    F_WRITE(b, CF, new TruncInst( v,
                                    Type::getInt1Ty(b->getContext()),
                                    "",
                                    b));

    return;
}

template <int width>
static void WriteAFAddSub(BasicBlock *b, Value *res, Value *o1, Value *o2) {

    Value   *v1 = BinaryOperator::CreateXor(res, o1, "", b);
    Value   *v2 = BinaryOperator::CreateXor(v1, o2, "", b);
    Value   *v3 = BinaryOperator::CreateAnd(v2, CONST_V<width>(b, 16), "", b);

    Value   *c = new ICmpInst(*b, CmpInst::ICMP_NE, v3, CONST_V<width>(b, 0));

    F_WRITE(b, AF, c);

    return;
}

template <int width>
static void WriteAF2(BasicBlock *b, Value *r, Value *lhs, Value *rhs) {
    //this will implement the (r ^ lhs ^ rhs) & 0x10 approach used by VEX
    //but it will also assume that the values as input are full width
    Value   *t1 = 
        BinaryOperator::CreateXor(r, lhs, "", b);
    Value   *t2 =
        BinaryOperator::CreateXor(t1, rhs, "", b);
    Value   *t3 = 
        BinaryOperator::CreateAnd(t2, CONST_V<width>(b, 0x10), "", b);
    Value   *cr = 
        new ICmpInst(*b, CmpInst::ICMP_NE, t3, CONST_V<width>(b, 0));

    F_WRITE(b, AF, cr);
    return;
}

template <int width>
static void WriteCFAdd(BasicBlock *b, Value *res, Value *argL) {
    //cf = res < argL
    Value   *cmpRes = new ICmpInst(*b, CmpInst::ICMP_ULT, res, argL);

    F_WRITE(b, CF, cmpRes);

    return;
}

static void WriteCFSub(BasicBlock *b, Value *argL, Value *argR) {
    Value   *cmpRes = new ICmpInst(*b, CmpInst::ICMP_ULT, argL, argR);

    F_WRITE(b, CF, cmpRes);
    return;
}

template <int width>
static void WriteOFSub(BasicBlock *b, Value *res, Value *lhs, Value *rhs) {
    //of = lshift((lhs ^ rhs ) & (lhs ^ res), 12 - width) & 2048
    //where lshift is written as if n >= 0, x << n, else x >> (-n)

    Value   *xor1 = BinaryOperator::CreateXor(lhs, rhs, "", b);
    Value   *xor2 = BinaryOperator::CreateXor(lhs, res, "", b);

    Value  *anded = BinaryOperator::CreateAnd(xor1, xor2, "", b);

    Value   *shifted = NULL;
    // extract sign bit
    switch(width) {
        case 8:
        case 16:
        case 32:
        case 64:
            shifted =
                BinaryOperator::CreateLShr(anded, CONST_V<width>(b, width-1), "", b);
            break;

        default:
            throw TErr(__LINE__, __FILE__, "Invalid bitwidth");
    }

    TASSERT(shifted != NULL, "");

    //truncate anded1
    Value   *trunced = 
        new TruncInst(shifted, Type::getInt1Ty(b->getContext()), "", b);

    //write to OF
    F_WRITE(b, OF, trunced);

    return;
}


template <int width>
static void WriteOFAdd(BasicBlock *b, Value *res, Value *lhs, Value *rhs) {
    //of = lshift((lhs ^ rhs ^ -1) & (lhs ^ res), 12 - width) & 2048
    //where lshift is written as if n >= 0, x << n, else x >> (-n)

    Value   *xor1 = BinaryOperator::CreateXor(lhs, rhs, "", b);
    Value   *xor2 = BinaryOperator::CreateXor(xor1, CONST_V<width>(b, -1), "", b);
    Value   *xor3 = BinaryOperator::CreateXor(lhs, res, "", b);

    Value  *anded = BinaryOperator::CreateAnd(xor2, xor3, "", b);

    Value   *shifted = NULL;
    // shifts corrected to always place the OF bit
    // in the bit 0 posision. This way it works for
    // all sized ints
    switch(width) {
        case 8:
            //lshift by 4
            shifted = 
                BinaryOperator::CreateLShr(anded, CONST_V<width>(b, 11-4), "", b);
            break;
        //in these two cases, we rshift instead
        case 16:
            //rshift by 4
            shifted = 
                BinaryOperator::CreateLShr(anded, CONST_V<width>(b, 11+4), "", b);
            break;
        case 32:
            //rshift by 20
            shifted = 
                BinaryOperator::CreateLShr(anded, CONST_V<width>(b, 11+20), "", b);
            break;
        case 64:
            //rshift by 52
            shifted =
                BinaryOperator::CreateLShr(anded, CONST_V<width>(b, 11+52), "", b);
            break;

        default:
            throw TErr(__LINE__, __FILE__, "Invalid bitwidth");
    }

    TASSERT(shifted != NULL, "");

    //and by 1
    Value   *anded1 = 
        BinaryOperator::CreateAnd(shifted, CONST_V<width>(b, 1), "", b);

    //truncate anded1
    Value   *trunced = 
        new TruncInst(anded1, Type::getInt1Ty(b->getContext()), "", b);

    //write to OF
    F_WRITE(b, OF, trunced);

    return;
}

template <int width>
static void WritePF(BasicBlock *b, Value *written) {
    Module  *M = b->getParent()->getParent();
    //truncate the written value to one byte
    //if the width is already 8, we don't need to do this
    Value   *lsb;
    if( width > 8 ) {
        lsb = new TruncInst(   written, 
                                Type::getInt8Ty(b->getContext()), 
                                "", 
                                b);
    } else {
        lsb = written; 
    }

    //use llvm.ctpop.i8 to count the bits set in this byte
    Type            *s = { Type::getInt8Ty(b->getContext()) };
    Function        *popCntFun = 
        Intrinsic::getDeclaration(M, Intrinsic::ctpop, s);
    vector<Value*>  countArgs;

    countArgs.push_back(lsb);

    Value       *count = (Value*) noAliasMCSemaScope(CallInst::Create(popCntFun, countArgs, "", b));

    //truncate the count to a bit
    Type    *ty = Type::getInt1Ty(b->getContext());
    Value   *countTrunc = new TruncInst(count, ty, "", b);

    //negate that bit via xor 1
    Value   *neg = 
        BinaryOperator::CreateXor( countTrunc, CONST_V<1>(b, 1), "", b);

    //write that bit to PF
    F_WRITE(b, PF, neg);
    return;
}

template <int width>
static void WriteSF(BasicBlock *b, Value *written) {
    //%1 = SIGNED CMP %written < 0
    //Value   *scmp = new ICmpInst(   *b,
    //                                ICmpInst::ICMP_SLT,
    //                                written,
    //                                CONST_V<width>(b, 0));

    // extract sign bit
    Value *signBit = BinaryOperator::CreateLShr(written, CONST_V<width>(b, width-1), "", b);
    Value *trunc = new TruncInst(signBit, Type::getInt1Ty(b->getContext()), "", b);
    F_WRITE(b, SF, trunc);
    return;
}
