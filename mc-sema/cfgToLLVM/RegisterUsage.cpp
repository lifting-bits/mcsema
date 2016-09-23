/*
Copyright (c) 2015, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of the {organization} nor the names of its
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

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include "llvm/Support/Debug.h"
#include "X86Subtarget.h"
#include "RegisterUsage.h"
#include "TransExcn.h"
#include <stdexcept>
#include <iostream>

#include "../common/to_string.h"

using namespace std;
using namespace llvm;

namespace x86 {
std::map<MCSemaRegs, RegInfo> REG_TO_OFFSET_MAP {
    {EAX, {0, "EAX"}},
    {EBX, {1, "EBX"}},
    {ECX, {2, "ECX"}},
    {EDX, {3, "EDX"}},
    {ESI, {4, "ESI"}},
    {EDI, {5, "EDI"}},
    {ESP, {6, "ESP"}},
    {EBP, {7, "EBP"}},
    {CF, {8, "CF"}},
    {PF, {9, "PF"}},
    {AF, {10, "AF"}},
    {ZF, {11, "ZF"}},
    {SF, {12, "SF"}},
    {OF, {13, "OF"}},
    {DF, {14, "DF"}},
    {ST0, {15, "STi"}}, // NOT A MISTAKE. These},
    {ST1, {15, "STi"}}, // are in a separate structure},
    {ST2, {15, "STi"}},
    {ST3, {15, "STi"}},
    {ST4, {15, "STi"}},
    {ST5, {15, "STi"}},
    {ST6, {15, "STi"}},
    {ST7, {15, "STi"}},
    {FPU_B, {16, "FPU_B"}},
    {FPU_C3, {17, "FPU_C3"}},
    {FPU_TOP, {18, "FPU_TOP"}},
    {FPU_C2, {19, "FPU_C2"}},
    {FPU_C1, {20, "FPU_C1"}},
    {FPU_C0, {21, "FPU_C0"}},
    {FPU_ES, {22, "FPU_ES"}},
    {FPU_SF, {23, "FPU_SF"}},
    {FPU_PE, {24, "FPU_PE"}},
    {FPU_UE, {25, "FPU_UE"}},
    {FPU_OE, {26, "FPU_OE"}},
    {FPU_ZE, {27, "FPU_ZE"}},
    {FPU_DE, {28, "FPU_DE"}},
    {FPU_IE, {29, "FPU_IE"}},
    {FPU_X, {30, "FPU_X"}},
    {FPU_RC, {31, "FPU_RC"}},
    {FPU_PC, {32, "FPU_PC"}},
    {FPU_PM, {33, "FPU_PM"}},
    {FPU_UM, {34, "FPU_UM"}},
    {FPU_OM, {35, "FPU_OM"}},
    {FPU_ZM, {36, "FPU_ZM"}},
    {FPU_DM, {37, "FPU_DM"}},
    {FPU_IM, {38, "FPU_IM"}},
    {FPU_TAG, {39, "FPU_TAG"}},
    {FPU_LASTIP_SEG, {40, "FPU_LASTIP_SEG"}},
    {FPU_LASTIP_OFF, {41, "FPU_LASTIP_OFF"}},
    {FPU_LASTDATA_SEG, {42, "FPU_LASTDATA_SEG"}},
    {FPU_LASTDATA_OFF, {43, "FPU_LASTDATA_OFF"}},
    {FPU_FOPCODE, {44, "FPU_FOPCODE"}},
    {XMM0, {45, "XMM0"}},
    {XMM1, {46, "XMM1"}},
    {XMM2, {47, "XMM2"}},
    {XMM3, {48, "XMM3"}},
    {XMM4, {49, "XMM4"}},
    {XMM5, {50, "XMM5"}},
    {XMM6, {51, "XMM6"}},
    {XMM7, {52, "XMM7"}},
    {STACK_BASE, {53, "STACK_BASE"}},
    {STACK_LIMIT, {54, "STACK_LIMIT"}}
};

StringRef getRegisterName(MCSemaRegs reg) {
    try {
        return REG_TO_OFFSET_MAP.at(reg).name;
    } catch (const std::out_of_range &oor) {
        std::cerr << __FILE__ << ":" << __LINE__ << ": Could not find register name for: " << reg << std::endl;
        std::cerr <<  oor.what() << std::endl;
        throw;
    }
}

int getRegisterOffset(MCSemaRegs reg) {
    try {
        return REG_TO_OFFSET_MAP.at(reg).position;
    } catch (const std::out_of_range &oor) {
        std::cerr << __FILE__ << ":" << __LINE__ << ": Could not find register offset for: " << reg << std::endl;
        std::cerr <<  oor.what() << std::endl;
        throw;
    }
}

Value *lookupLocal(Function *F, MCSemaRegs reg) {
    BasicBlock  *entry = &F->getEntryBlock();
    BasicBlock::iterator    it = entry->begin();

    std::string localName = std::string(x86::getRegisterName(reg))+"_val";
    while(it != entry->end() ) {
        Value   *v = it;

        if( v->getName() == localName ) {
            return v;
        }

        ++it;
    }
    assert(0);
    throw TErr (__LINE__, __FILE__, "localname: "+localName+" is not found");
    return nullptr;
}

int mapPlatRegToOffset(unsigned reg) {
    switch(reg) {
        case X86::DH:
        case X86::CH:
        case X86::BH:
        case X86::AH:
            return 8;
            break;
        case X86::AX:
        case X86::AL:
        case X86::EAX:
        case X86::BX:
        case X86::BL:
        case X86::EBX:
        case X86::CX:
        case X86::CL:
        case X86::ECX:
        case X86::DX:
        case X86::DL:
        case X86::EDX:
        case X86::SI:
        case X86::ESI:
        case X86::DI:
        case X86::EDI:
        case X86::SP:
        case X86::ESP:
        case X86::BP:
        case X86::EBP:

        case X86::ST0:
        case X86::ST1:
        case X86::ST2:
        case X86::ST3:
        case X86::ST4:
        case X86::ST5:
        case X86::ST6:
        case X86::ST7:

        case X86::XMM0:
        case X86::XMM1:
        case X86::XMM2:
        case X86::XMM3:
        case X86::XMM4:
        case X86::XMM5:
        case X86::XMM6:
        case X86::XMM7:
            return 0;
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Reg type "+to_string<unsigned>(reg, dec)+" is unknown");
    }

    return -1;
}

Value *MCRegToValue(BasicBlock *b, unsigned reg) {
    unsigned realReg = reg;
    switch(reg)
    {
        case X86::AX:
        case X86::AH:
        case X86::AL:
            realReg = X86::EAX;
            break;
        case X86::BX:
        case X86::BH:
        case X86::BL:
            realReg = X86::EBX;
            break;
        case X86::CX:
        case X86::CH:
        case X86::CL:
            realReg = X86::ECX;
            break;
        case X86::DX:
        case X86::DH:
        case X86::DL:
            realReg = X86::EDX;
            break;
        case X86::SI:
            realReg = X86::ESI;
            break;
        case X86::DI:
            realReg = X86::EDI;
            break;
        case X86::SP:
            realReg = X86::ESP;
            break;
        case X86::BP:
            realReg = X86::EBP;
            break;
        default:
            break;
    }
    Function    *F = b->getParent();

    return lookupLocal(F, (MCSemaRegs)realReg);
}
}

namespace x86_64 {
std::map<MCSemaRegs, RegInfo> REG_TO_OFFSET_MAP {
    {EAX, {0, "RAX"}},
	{RAX, {0, "RAX"}},
	{EBX, {1, "RBX"}},
    {RBX, {1, "RBX"}},
	{ECX, {2, "RCX"}},
    {RCX, {2, "RCX"}},
	{EDX, {3, "RDX"}},
    {RDX, {3, "RDX"}},
    {SIL, {4, "RSI"}},
	{ESI, {4, "RSI"}},
    {RSI, {4, "RSI"}},
    {DIL, {5, "RDI"}},
	{EDI, {5, "RDI"}},
    {RDI, {5, "RDI"}},
	{ESP, {6, "RSP"}},
    {RSP, {6, "RSP"}},
	{EBP, {7, "RBP"}},
    {RBP, {7, "RBP"}},
	{R8,  {8, "R8"}},
	{R9,  {9, "R9"}},
	{R10, {10, "R10"}},
	{R11, {11, "R11"}},
	{R12, {12, "R12"}},
	{R13, {13, "R13"}},
	{R14, {14, "R14"}},
	{R15, {15, "R15"}},
	{RIP, {16, "RIP"}},
    {CF, {17, "CF"}},
    {PF, {18, "PF"}},
    {AF, {19, "AF"}},
    {ZF, {20, "ZF"}},
    {SF, {21, "SF"}},
    {OF, {22, "OF"}},
    {DF, {23, "DF"}},
    {ST0, {24, "STi"}},
    {ST1, {24, "STi"}},
    {ST2, {24, "STi"}},
    {ST3, {24, "STi"}},
    {ST4, {24, "STi"}},
    {ST5, {24, "STi"}},
    {ST6, {24, "STi"}},
    {ST7, {24, "STi"}},
    {FPU_B, {25, "FPU_B"}},
    {FPU_C3, {26, "FPU_C3"}},
    {FPU_TOP, {27, "FPU_TOP"}},
    {FPU_C2, {28, "FPU_C2"}},
    {FPU_C1, {29, "FPU_C1"}},
    {FPU_C0, {30, "FPU_C0"}},
    {FPU_ES, {31, "FPU_ES"}},
    {FPU_SF, {32, "FPU_SF"}},
    {FPU_PE, {33, "FPU_PE"}},
    {FPU_UE, {34, "FPU_UE"}},
    {FPU_OE, {35, "FPU_OE"}},
    {FPU_ZE, {36, "FPU_ZE"}},
    {FPU_DE, {37, "FPU_DE"}},
    {FPU_IE, {38, "FPU_IE"}},
    {FPU_X, {39, "FPU_X"}},
    {FPU_RC, {40, "FPU_RC"}},
    {FPU_PC, {41, "FPU_PC"}},
    {FPU_PM, {42, "FPU_PM"}},
    {FPU_UM, {43, "FPU_UM"}},
    {FPU_OM, {44, "FPU_OM"}},
    {FPU_ZM, {45, "FPU_ZM"}},
    {FPU_DM, {46, "FPU_DM"}},
    {FPU_IM, {47, "FPU_IM"}},
    {FPU_TAG, {48, "FPU_TAG"}},
    {FPU_LASTIP_SEG, {49, "FPU_LASTIP_SEG"}},
    {FPU_LASTIP_OFF, {50, "FPU_LASTIP_OFF"}},
    {FPU_LASTDATA_SEG, {51, "FPU_LASTDATA_SEG"}},
    {FPU_LASTDATA_OFF, {52, "FPU_LASTDATA_OFF"}},
    {FPU_FOPCODE, {53, "FPU_FOPCODE"}},
    {XMM0, {54, "XMM0"}},
    {XMM1, {55, "XMM1"}},
    {XMM2, {56, "XMM2"}},
    {XMM3, {57, "XMM3"}},
    {XMM4, {58, "XMM4"}},
    {XMM5, {59, "XMM5"}},
    {XMM6, {60, "XMM6"}},
    {XMM7, {61, "XMM7"}},
	{XMM8, {62, "XMM8"}},
    {XMM9, {63, "XMM9"}},
    {XMM10, {64, "XMM10"}},
    {XMM11, {65, "XMM11"}},
    {XMM12, {66, "XMM12"}},
    {XMM13, {67, "XMM13"}},
    {XMM14, {68, "XMM14"}},
    {XMM15, {69, "XMM15"}},
    {STACK_BASE, {70, "STACK_BASE"}},
    {STACK_LIMIT, {71, "STACK_LIMIT"}}
};

StringRef getRegisterName(MCSemaRegs reg) {
    try {
        return REG_TO_OFFSET_MAP.at(reg).name;
    } catch (const std::out_of_range &oor) {
        std::cerr << __FILE__ << ":" << __LINE__ << ": Could not find register name for: " << reg << std::endl;
        std::cerr <<  oor.what() << std::endl;
        throw;
    }
}

int getRegisterOffset(MCSemaRegs reg) {
    try {
        return REG_TO_OFFSET_MAP.at(reg).position;
    } catch (const std::out_of_range &oor) {
        std::cerr << __FILE__ << ":" << __LINE__ << ": Could not find register offset for: " << reg << std::endl;
        std::cerr <<  oor.what() << std::endl;
        throw;
    }
}

Value *lookupLocal(Function *F, MCSemaRegs reg) {
    BasicBlock  *entry = &F->getEntryBlock();
    BasicBlock::iterator    it = entry->begin();

    std::string localName = std::string(x86_64::getRegisterName(reg))+"_val";
    while(it != entry->end() ) {
        Value   *v = it;

        if( v->getName() == localName ) {
            return v;
        }

        ++it;
    }

    throw TErr (__LINE__, __FILE__, "localname: "+localName+" is not found");
    return nullptr;
}

int mapPlatRegToOffset(unsigned reg) {
    switch(reg) {
        case X86::DH: 	case X86::CH:	case X86::BH: 	case X86::AH:
            return 8;
            break;
        case X86::AX:	case X86::AL:	case X86::EAX:	case X86::RAX:
        case X86::BX:	case X86::BL:	case X86::EBX:	case X86::RBX:
        case X86::CX:   case X86::CL:   case X86::ECX:	case X86::RCX:
        case X86::DX:	case X86::DL:	case X86::EDX:	case X86::RDX:
		case X86::SIL:  case X86::SI:   case X86::ESI:	case X86::RSI:
		case X86::DIL:  case X86::DI:   case X86::EDI:	case X86::RDI:
		case X86::SPL:  case X86::SP:   case X86::ESP:	case X86::RSP:
		case X86::BPL:  case X86::BP:   case X86::EBP:	case X86::RBP:
		case X86::R8B:	case X86::R8W:	case X86::R8D:	case X86::R8:
        case X86::R9B:  case X86::R9W:  case X86::R9D:  case X86::R9:
        case X86::R10B: case X86::R10W: case X86::R10D: case X86::R10:
        case X86::R11B: case X86::R11W: case X86::R11D: case X86::R11:
        case X86::R12B: case X86::R12W: case X86::R12D: case X86::R12:
        case X86::R13B: case X86::R13W: case X86::R13D: case X86::R13:
        case X86::R14B: case X86::R14W: case X86::R14D: case X86::R14:
        case X86::R15B: case X86::R15W: case X86::R15D: case X86::R15:


        case X86::ST0:	case X86::ST1:	case X86::ST2:	case X86::ST3:
        case X86::ST4:	case X86::ST5:	case X86::ST6:	case X86::ST7:

        case X86::XMM0:	case X86::XMM1:	case X86::XMM2:	case X86::XMM3:
        case X86::XMM4: case X86::XMM5: case X86::XMM6: case X86::XMM7:
		case X86::XMM8:	case X86::XMM9:	case X86::XMM10:case X86::XMM11:
		case X86::XMM12:case X86::XMM13:case X86::XMM14:case X86::XMM15:
            return 0;
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Reg type "+to_string<unsigned>(reg, dec)+" is unknown");
    }

    return -1;
}

Value *MCRegToValue(BasicBlock *b, unsigned reg) {
    unsigned realReg = reg;
    switch(reg)
    {
        case X86::AX:	case X86::AH:	case X86::AL:	case X86::EAX:
            realReg = X86::RAX;
            break;
        case X86::BX:	case X86::BH:	case X86::BL:	case X86::EBX:
            realReg = X86::RBX;
            break;
        case X86::CX:	case X86::CH:	case X86::CL:	case X86::ECX:
            realReg = X86::RCX;
            break;
        case X86::DX:	case X86::DH:	case X86::DL:	case X86::EDX:
            realReg = X86::RDX;
            break;
        case X86::SIL:	case X86::SI:	case X86::ESI:
            realReg = X86::RSI;
            break;
        case X86::DIL:	case X86::DI:	case X86::EDI:
            realReg = X86::RDI;
            break;
        case X86::SPL:	case X86::SP:	case X86::ESP:
            realReg = X86::RSP;
            break;
        case X86::BPL:	case X86::BP:	case X86::EBP:
            realReg = X86::RBP;
            break;
        case X86::R8B:	case X86::R8W:	case X86::R8D:	case X86::R8:
			realReg = X86::R8;
        	break;
        case X86::R9B:	case X86::R9W:	case X86::R9D:	case X86::R9:
			realReg = X86::R9;
        	break;
        case X86::R10B:	case X86::R10W:	case X86::R10D:	case X86::R10:
			realReg = X86::R10;
        	break;
        case X86::R11B:	case X86::R11W:	case X86::R11D:	case X86::R11:
			realReg = X86::R11;
        	break;
        case X86::R12B:	case X86::R12W:	case X86::R12D:	case X86::R12:
			realReg = X86::R12;
        	break;
        case X86::R13B:	case X86::R13W:	case X86::R13D:	case X86::R13:
			realReg = X86::R13;
        	break;
        case X86::R14B:	case X86::R14W:	case X86::R14D:	case X86::R14:
			realReg = X86::R14;
        	break;
        case X86::R15B:	case X86::R15W:	case X86::R15D:	case X86::R15:
			realReg = X86::R15;
        	break;
        default:
            break;
    }
    Function    *F = b->getParent();

    return lookupLocal(F, (MCSemaRegs)realReg);
}

}


