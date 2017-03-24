///* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */
//
//#ifndef MC_SEMA_ARCH_REGISTER_H_
//#define MC_SEMA_ARCH_REGISTER_H_
//
//#include <string>
//
//namespace llvm {
//
//class BasicBlock;
//class Function;
//class Module;
//class StructType;
//
//}  // namespace llvm
//
//using MCSemaRegs = unsigned;
//
//extern const std::string &(*ArchRegisterName)(MCSemaRegs);
//extern MCSemaRegs (*ArchRegisterNumber)(const std::string &);
//extern unsigned (*ArchRegisterOffset)(MCSemaRegs);
//extern MCSemaRegs (*ArchRegisterParent)(MCSemaRegs);
//extern void (*ArchAllocRegisterVars)(llvm::BasicBlock *);
//extern unsigned (*ArchRegisterSize)(MCSemaRegs);
//extern llvm::StructType *(*ArchRegStateStructType)(void);
//extern llvm::Function *(*ArchGetOrCreateRegStateTracer)(llvm::Module *);
//
//#define getRegisterName ArchRegisterName
//#define getRegisterFromName ArchRegisterNumber
//#define getRegisterOffset ArchRegisterOffset
//
//#endif  // MC_SEMA_ARCH_REGISTER_H_
