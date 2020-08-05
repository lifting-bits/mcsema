/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MCSEMA_ARCH_X86_RUNTIME_REGISTERS_H_
#define MCSEMA_ARCH_X86_RUNTIME_REGISTERS_H_

#define AH gpr.rax.byte.high
#define BH gpr.rbx.byte.high
#define CH gpr.rcx.byte.high
#define DH gpr.rdx.byte.high
#define AL gpr.rax.byte.low
#define BL gpr.rbx.byte.low
#define CL gpr.rcx.byte.low
#define DL gpr.rdx.byte.low

#define SIL gpr.rsi.byte.low
#define DIL gpr.rdi.byte.low
#define SPL gpr.rsp.byte.low
#define BPL gpr.rbp.byte.low
#define R8B gpr.r8.byte.low
#define R9B gpr.r9.byte.low
#define R10B gpr.r10.byte.low
#define R11B gpr.r11.byte.low
#define R12B gpr.r12.byte.low
#define R13B gpr.r13.byte.low
#define R14B gpr.r14.byte.low
#define R15B gpr.r15.byte.low

#define AX gpr.rax.word
#define BX gpr.rbx.word
#define CX gpr.rcx.word
#define DX gpr.rdx.word
#define SI gpr.rsi.word
#define DI gpr.rdi.word
#define SP gpr.rsp.word
#define BP gpr.rbp.word

#define R8W gpr.r8.word
#define R9W gpr.r9.word
#define R10W gpr.r10.word
#define R11W gpr.r11.word
#define R12W gpr.r12.word
#define R13W gpr.r13.word
#define R14W gpr.r14.word
#define R15W gpr.r15.word
#define IP gpr.rip.word

#define EAX gpr.rax.dword
#define EBX gpr.rbx.dword
#define ECX gpr.rcx.dword
#define EDX gpr.rdx.dword
#define ESI gpr.rsi.dword
#define EDI gpr.rdi.dword
#define ESP gpr.rsp.dword
#define EBP gpr.rbp.dword
#define EIP gpr.rip.dword

#define R8D gpr.r8.dword
#define R9D gpr.r9.dword
#define R10D gpr.r10.dword
#define R11D gpr.r11.dword
#define R12D gpr.r12.dword
#define R13D gpr.r13.dword
#define R14D gpr.r14.dword
#define R15D gpr.r15.dword

#define RAX gpr.rax.aword
#define RBX gpr.rbx.aword
#define RCX gpr.rcx.aword
#define RDX gpr.rdx.aword
#define RSI gpr.rsi.aword
#define RDI gpr.rdi.aword
#define RSP gpr.rsp.aword
#define RBP gpr.rbp.aword
#define R8 gpr.r8.aword
#define R9 gpr.r9.aword
#define R10 gpr.r10.aword
#define R11 gpr.r11.aword
#define R12 gpr.r12.aword
#define R13 gpr.r13.aword
#define R14 gpr.r14.aword
#define R15 gpr.r15.aword
#define RIP gpr.rip.aword

#define SS seg.ss
#define ES seg.es
#define GS seg.gs
#define FS seg.fs
#define DS seg.ds
#define CS seg.cs

#define SS_BASE
#define ES_BASE
#define GS_BASE addr.gs_base.IF_64BIT_ELSE(qword, dword)
#define FS_BASE addr.fs_base.IF_64BIT_ELSE(qword, dword)
#define DS_BASE
#define CS_BASE

#define ZMM0 vec[0].zmm
#define ZMM1 vec[1].zmm
#define ZMM2 vec[2].zmm
#define ZMM3 vec[3].zmm
#define ZMM4 vec[4].zmm
#define ZMM5 vec[5].zmm
#define ZMM6 vec[6].zmm
#define ZMM7 vec[7].zmm
#define ZMM8 vec[8].zmm
#define ZMM9 vec[9].zmm
#define ZMM10 vec[10].zmm
#define ZMM11 vec[11].zmm
#define ZMM12 vec[12].zmm
#define ZMM13 vec[13].zmm
#define ZMM14 vec[14].zmm
#define ZMM15 vec[15].zmm
#define ZMM16 vec[16].zmm
#define ZMM17 vec[17].zmm
#define ZMM18 vec[18].zmm
#define ZMM19 vec[19].zmm
#define ZMM20 vec[20].zmm
#define ZMM21 vec[21].zmm
#define ZMM22 vec[22].zmm
#define ZMM23 vec[23].zmm
#define ZMM24 vec[24].zmm
#define ZMM25 vec[25].zmm
#define ZMM26 vec[26].zmm
#define ZMM27 vec[27].zmm
#define ZMM28 vec[28].zmm
#define ZMM29 vec[29].zmm
#define ZMM30 vec[30].zmm
#define ZMM31 vec[31].zmm

#define YMM0 vec[0].ymm
#define YMM1 vec[1].ymm
#define YMM2 vec[2].ymm
#define YMM3 vec[3].ymm
#define YMM4 vec[4].ymm
#define YMM5 vec[5].ymm
#define YMM6 vec[6].ymm
#define YMM7 vec[7].ymm
#define YMM8 vec[8].ymm
#define YMM9 vec[9].ymm
#define YMM10 vec[10].ymm
#define YMM11 vec[11].ymm
#define YMM12 vec[12].ymm
#define YMM13 vec[13].ymm
#define YMM14 vec[14].ymm
#define YMM15 vec[15].ymm

#define YMM16 vec[16].ymm
#define YMM17 vec[17].ymm
#define YMM18 vec[18].ymm
#define YMM19 vec[19].ymm
#define YMM20 vec[20].ymm
#define YMM21 vec[21].ymm
#define YMM22 vec[22].ymm
#define YMM23 vec[23].ymm
#define YMM24 vec[24].ymm
#define YMM25 vec[25].ymm
#define YMM26 vec[26].ymm
#define YMM27 vec[27].ymm
#define YMM28 vec[28].ymm
#define YMM29 vec[29].ymm
#define YMM30 vec[30].ymm
#define YMM31 vec[31].ymm

#define XMM0 vec[0].xmm
#define XMM1 vec[1].xmm
#define XMM2 vec[2].xmm
#define XMM3 vec[3].xmm
#define XMM4 vec[4].xmm
#define XMM5 vec[5].xmm
#define XMM6 vec[6].xmm
#define XMM7 vec[7].xmm

#define XMM8 vec[8].xmm
#define XMM9 vec[9].xmm
#define XMM10 vec[10].xmm
#define XMM11 vec[11].xmm
#define XMM12 vec[12].xmm
#define XMM13 vec[13].xmm
#define XMM14 vec[14].xmm
#define XMM15 vec[15].xmm

#define XMM16 vec[16].xmm
#define XMM17 vec[17].xmm
#define XMM18 vec[18].xmm
#define XMM19 vec[19].xmm
#define XMM20 vec[20].xmm
#define XMM21 vec[21].xmm
#define XMM22 vec[22].xmm
#define XMM23 vec[23].xmm
#define XMM24 vec[24].xmm
#define XMM25 vec[25].xmm
#define XMM26 vec[26].xmm
#define XMM27 vec[27].xmm
#define XMM28 vec[28].xmm
#define XMM29 vec[29].xmm
#define XMM30 vec[30].xmm
#define XMM31 vec[31].xmm

#define ST0 st.elems[0].val
#define ST1 st.elems[1].val
#define ST2 st.elems[2].val
#define ST3 st.elems[3].val
#define ST4 st.elems[4].val
#define ST5 st.elems[5].val
#define ST6 st.elems[6].val
#define ST7 st.elems[7].val

#define MM0 mmx.elems[0].val.qwords.elems[0]
#define MM1 mmx.elems[1].val.qwords.elems[0]
#define MM2 mmx.elems[2].val.qwords.elems[0]
#define MM3 mmx.elems[3].val.qwords.elems[0]
#define MM4 mmx.elems[4].val.qwords.elems[0]
#define MM5 mmx.elems[5].val.qwords.elems[0]
#define MM6 mmx.elems[6].val.qwords.elems[0]
#define MM7 mmx.elems[7].val.qwords.elems[0]

#define AF aflag.af
#define CF aflag.cf
#define DF aflag.df
#define OF aflag.of
#define PF aflag.pf
#define SF aflag.sf
#define ZF aflag.zf

#endif  // MCSEMA_ARCH_X86_RUNTIME_REGISTERS_H_
