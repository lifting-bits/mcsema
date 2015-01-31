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
#include "pin.H"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <map>
#include <string>
#include <sstream>
#include <utility>
#include <algorithm>
#include <cassert>
#include <limits>
#include <cstring>
#if !defined(__APPLE__)
	#include <cstdint>
#endif

using namespace std;

#define AF ( 1 << 4  )
#define SF ( 1 << 7  )
#define ZF ( 1 << 6  )
#define PF ( 1 << 2  ) 
#define OF ( 1 << 11 )
#define CF ( 1 << 0  )
#define DF ( 1 << 10 )

#define ARRAYSIZE(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

/* ================================================================== */
// Types and declarations
/* ================================================================== */

//types for tracking register states
typedef vector<ADDRINT>         regWrittenT;
typedef map<UINT32,regWrittenT> writtenSetsT; 

typedef vector<ADDRINT>             valVecT;
typedef pair<UINT32, valVecT>       valWidthT;
typedef map<ADDRINT, valWidthT>     writtenMemT;
typedef map<UINT32, writtenMemT>    memSetsT;

typedef union {
    long double st;
    uint8_t pad[16];
} streg;

typedef union {
    uint8_t pad[16];
} xmmreg;

#ifdef _MSC_VER
#pragma pack (1)
#endif

typedef struct
#ifdef _MSC_VER
__declspec(align(16))
#endif
 _fxsave {
    uint16_t    FCW;
    uint16_t    FSW;
    uint8_t     FTW;
    uint8_t     res0;
    uint16_t    FOP;
    uint32_t    FPUIP;
    uint16_t    FPUCS;
    uint16_t    res1;
    uint32_t    FPUDP;
    uint16_t    FPUDS;
    uint16_t    res2;
    uint32_t    MXCSR;
    uint32_t    MXCSR_MASK;
    // FPU/MMX registers
    streg ST[8];

    // SSE
    xmmreg XMM[8];
    
    // reserved fields
    uint8_t res3[176];

    // available fields
    uint8_t avail[48];
} 
#ifndef _MSC_VER
__attribute__((aligned(16),packed)) 
#endif
fxsave;

#ifdef _MSVC_VER
#pragma pack ()
#endif


struct flagentry {
    std::string name;
    uint16_t mask;
    uint16_t shift;
};

flagentry FPU_FLAGS[] = {
    {"FPU_BUSY",    1, 15},
    {"FPU_C3",      1, 14},
    {"FPU_TOP",     7, 11},
    {"FPU_C2",      1, 10},
    {"FPU_C1",      1, 9},
    {"FPU_C0",      1, 8},
    {"FPU_ES",      1, 7},
    {"FPU_SF",      1, 6},
    {"FPU_PE",      1, 5},
    {"FPU_UE",      1, 4},
    {"FPU_OE",      1, 3},
    {"FPU_ZE",      1, 2},
    {"FPU_DE",      1, 1},
    {"FPU_IE",      1, 0}
};

flagentry FPU_CONTROL[] = {
    {"FPU_X",       1, 12},
    {"FPU_RC",      3, 10},
    {"FPU_PC",      3, 8},
    {"FPU_PM",      1, 5},
    {"FPU_UM",      1, 4},
    {"FPU_OM",      1, 3},
    {"FPU_ZM",      1, 2},
    {"FPU_DM",      1, 1},
    {"FPU_IM",      1, 0},
};

enum fpuflagname {
    FPU_BUSY = 0,
    FPU_C3, 
    FPU_TOP,
    FPU_C2, 
    FPU_C1, 
    FPU_C0, 
    FPU_ES, 
    FPU_SF, 
    FPU_PE, 
    FPU_UE, 
    FPU_OE, 
    FPU_ZE, 
    FPU_DE, 
    FPU_IE
}; 

struct PerThreadData {
    bool            tracing;
    UINT32          curTag;
};

/* ================================================================== */
// Global variables 
/* ================================================================== */

TLS_KEY tlsKey;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "tests.out", "specify file name for output");

fstream *outFile;


PerThreadData *getTls(THREADID id) {
    return static_cast<PerThreadData *>(PIN_GetThreadData(tlsKey, id));
}

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

UINT32 isSentinelIns(INS instr) {
    //sentinel instructions are MOV ESI, 0x18231943
    if( INS_IsMov(instr) ) {
        //get the first two operands
        if( INS_OperandIsReg(instr, 0) ) {
            REG r = INS_OperandReg(instr, 0);
            //is r esi?
            if( r == REG_ESI ) {
                //is the second operand an immediate?
                if( INS_OperandIsImmediate(instr, 1) ) {
                    UINT64  o = INS_OperandImmediate(instr, 1);
                    //mask off the lower 2 bytes
                    if( (o>>16) == 0x1823 ) {
                        //sweet, we matched the magic value
                        UINT64 j = o << 48;
                        j = j >> 48;
                        return j;
                    }
                }
            }
        }
    }

    return 0;
}

void makeupper(string &upme)
{
    std::transform(upme.begin(), upme.end(), upme.begin(), ::toupper);
}

string dumpFpuFlags(fxsave &fpu_regs) {
    string resstr;

    for(unsigned i = 0; i < sizeof(FPU_FLAGS)/sizeof(FPU_FLAGS[0]); i++)
    {
        flagentry& fe = FPU_FLAGS[i];
        resstr += fe.name + ":" + 
            decstr( ((fe.mask << fe.shift) & fpu_regs.FSW) >> fe.shift )  + "\n";
    }

    for(unsigned i = 0; i < sizeof(FPU_CONTROL)/sizeof(FPU_CONTROL[0]); i++)
    {
        flagentry& fe = FPU_CONTROL[i];
        resstr += fe.name + ":" + 
            decstr( ((fe.mask << fe.shift) & fpu_regs.FCW) >> fe.shift )  + "\n";
    }

    resstr += "FPUTW:" + decstr(fpu_regs.FTW) + "\n";
    resstr += "FPU_FOPCODE:" + decstr(fpu_regs.FOP) + "\n";

    return resstr;
}

string dumpRegisterState(const CONTEXT *ctx) {
    //the registers we care about, in an array 
    string          res;
    unsigned int    i;
    REG caredRegs[] = {
        REG_EDI, REG_ESI, REG_EBP, REG_ESP,
        REG_EAX, REG_EBX, REG_ECX, REG_EDX };
    FPSTATE fpstate;
    fxsave fpu_regs;
    
    for( i = 0; i < sizeof(caredRegs)/sizeof(REG); i++ ) {
        REG     r = caredRegs[i];
        string  rStr = REG_StringShort(r);
        makeupper(rStr);
        ADDRINT val = PIN_GetContextReg(ctx, r);

        res = res+rStr+":"+decstr(val)+"\n";
    }

    // read FPU state
    PIN_GetContextFPState(ctx, &fpstate);
    std::memcpy(&fpu_regs, &fpstate.fxsave_legacy, sizeof(fpu_regs));

    for(unsigned i = 0; 
        i < ARRAYSIZE(fpu_regs.ST);//sizeof(fpu_regs.ST)/sizeof(fpu_regs.ST[0]); 
	i++) {
	    stringstream ss;
	    for(unsigned j = 0; j < sizeof(fpu_regs.ST[0]); j++) {
		ss << std::setw(2) << std::setfill('0') << std::hex << (unsigned)fpu_regs.ST[i].pad[j] << " ";
	    }

	    res += "ST"+decstr(i)+":"+ss.str() + "\n";
    }
    
    for(unsigned i = 0;
        i < ARRAYSIZE(fpu_regs.XMM);
    i++) {
        stringstream ss;
        for(unsigned j = 0; j < sizeof(fpu_regs.XMM[0]); j++) {
        ss << std::setw(2) << std::setfill('0') << std::hex << (unsigned)fpu_regs.XMM[i].pad[j] << " ";
        }

        res += "XMM"+decstr(i)+":"+ss.str() + "\n";
    }

    //dump EFLAGS seperately
    ADDRINT efVal = PIN_GetContextReg(ctx, REG_EFLAGS);

    if( efVal & AF ) {
        res = res + "AF:1\n";
    } else {
        res = res + "AF:0\n";
    }

    if( efVal & CF ) {
        res = res + "CF:1\n";
    } else {
        res = res + "CF:0\n";
    }
    
    if( efVal & PF ) {
        res = res + "PF:1\n";
    } else {
        res = res + "PF:0\n";
    }

    if( efVal & ZF ) {
        res = res + "ZF:1\n";
    } else {
        res = res + "ZF:0\n";
    }

    if( efVal & OF ) {
        res = res + "OF:1\n";
    } else {
        res = res + "OF:0\n";
    }

    if( efVal & SF ) {
        res = res + "SF:1\n";
    } else {
        res = res + "SF:0\n";
    }
    
    if( efVal & DF ) {
        res = res + "DF:1\n";
    } else {
        res = res + "DF:0\n";
    }


    res += dumpFpuFlags(fpu_regs);

    return res;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

VOID toggleTrace(THREADID tid, UINT32 t, const CONTEXT *ctx) {
    //get per-thread information
    PerThreadData   *dt = getTls(tid);

    dt->tracing = !dt->tracing;
    if( dt->tracing ) {
        dt->curTag = t;
        //dump out current register state
        string s;
        s = "TESTCASE:"+decstr(t)+"\n";
        s = s + "INPUTSTATE\n";
        s = s + dumpRegisterState(ctx);
        outFile->write(s.c_str(), s.length());
        outFile->flush();
    } else {
        string s;
        s = "OUTPUTSTATE\n";
        s = s + dumpRegisterState(ctx);
        s = s + "ENDCASE\n";
        s = s + "\n";
        outFile->write(s.c_str(), s.length());
        outFile->flush();
        dt->curTag = 0;
    }

    return;
}

VOID onRegWrite(THREADID tid, REG r, ADDRINT v) {

    return;
}

VOID onMemWritePre(THREADID tid, ADDRINT addr) {

    return;
}

VOID onMemWritePost(THREADID tid, UINT32 width) {

    return;
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID OnInstr(INS ins, VOID *ctx) {

    //check and see if this is a sentinel instruction
    UINT32  v;
    if( ( v = isSentinelIns(ins) ) ) {
        //if it is, add a 'toggle tracing' analysis routine
        //and leave
        INS_InsertCall( ins, 
                        IPOINT_BEFORE, 
                        AFUNPTR(toggleTrace), 
                        IARG_THREAD_ID,
                        IARG_UINT32, v,
                        IARG_CONTEXT,
                        IARG_END);
    }

    return;
}

VOID ThreadStart(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v) {
    //allocate a new PerThreadData
    PerThreadData   *pd = new PerThreadData();

    pd->tracing = false;
    ASSERT(pd != NULL, "ALLOC FAILED");

    PIN_SetThreadData(tlsKey, pd, tid);

    return;
}

VOID ThreadFini(THREADID tid, const CONTEXT *ctx, INT32 flags, VOID *v) {
    //we can free our PerThreadData
    PerThreadData   *pd = getTls(tid);

    delete pd;

    return;
}

VOID Fini(INT32 c, VOID *v) {
    outFile->flush();
    delete outFile;
    return;
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
    // sanity check
    ASSERT(sizeof(fxsave) == 512, "fxsave not of correct size on this compiler");
    ASSERT(sizeof(fxsave) == sizeof(FXSAVE), "our definition of FXSAVE and Intel's are not the same size");

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    //register an instruction callback
    INS_AddInstrumentFunction(OnInstr, NULL);

    //register a thread create callback
    PIN_AddThreadStartFunction(ThreadStart, NULL);

    //register a thread end callback
    PIN_AddThreadFiniFunction(ThreadFini, NULL);

    //register a finalizer so we can close our output
    PIN_AddFiniFunction(Fini, NULL);

    //open the output file
    outFile = new fstream(KnobOutputFile.Value().c_str(),ios::out|ios::trunc);
   
    //begin instrumentation
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
