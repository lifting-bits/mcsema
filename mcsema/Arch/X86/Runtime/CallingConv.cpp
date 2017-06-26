#define HAS_FEATURE_AVX 1
#define HAS_FEATURE_AVX512 0
#define ADDRESS_SIZE_BITS 64

#include "remill/Arch/X86/Runtime/State.h"

namespace mcsema {

// TODO(car): generate as needed somehow
addr_t __mcsema_cdecl_arg_0(Memory *, State *) {
  // stack args
  // memory[rsp]
  return State->gpr->rsp;
}

addr_t __mcsema_cdecl_arg_1(Memory *, State *) {
  return State->gpr->rsp + 1*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_2(Memory *, State *) {
  return State->gpr->rsp + 2*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_3(Memory *, State *) {
  return State->gpr->rsp + 3*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_4(Memory *, State *) {
  return State->gpr->rsp + 4*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_5(Memory *, State *) {
  return State->gpr->rsp + 5*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_6(Memory *, State *) {
  return State->gpr->rsp + 6*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_7(Memory *, State *) {
  return State->gpr->rsp + 7*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_8(Memory *, State *) {
  return State->gpr->rsp + 8*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_9(Memory *, State *) {
  return State->gpr->rsp + 9*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_10(Memory *, State *) {
  return State->gpr->rsp + 10*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_11(Memory *, State *) {
  return State->gpr->rsp + 11*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_12(Memory *, State *) {
  return State->gpr->rsp + 12*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_13(Memory *, State *) {
  return State->gpr->rsp + 13*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_14(Memory *, State *) {
  return State->gpr->rsp + 14*14; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_15(Memory *, State *) {
  return State->gpr->rsp + 15*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_16(Memory *, State *) {
  return State->gpr->rsp + 16*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_17(Memory *, State *) {
  return State->gpr->rsp + 17*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_18(Memory *, State *) {
  return State->gpr->rsp + 18*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_19(Memory *, State *) {
  return State->gpr->rsp + 19*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_20(Memory *, State *) {
  return State->gpr->rsp + 20*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_21(Memory *, State *) {
  return State->gpr->rsp + 21*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_22(Memory *, State *) {
  return State->gpr->rsp + 22*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_23(Memory *, State *) {
  return State->gpr->rsp + 23*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_24(Memory *, State *) {
  return State->gpr->rsp + 24*24; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_25(Memory *, State *) {
  return State->gpr->rsp + 25*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_26(Memory *, State *) {
  return State->gpr->rsp + 26*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_27(Memory *, State *) {
  return State->gpr->rsp + 27*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_28(Memory *, State *) {
  return State->gpr->rsp + 28*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_29(Memory *, State *) {
  return State->gpr->rsp + 29*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_31(Memory *, State *) {
  return State->gpr->rsp + 31*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_32(Memory *, State *) {
  return State->gpr->rsp + 32*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_33(Memory *, State *) {
  return State->gpr->rsp + 33*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_34(Memory *, State *) {
  return State->gpr->rsp + 34*34; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_35(Memory *, State *) {
  return State->gpr->rsp + 35*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_36(Memory *, State *) {
  return State->gpr->rsp + 36*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_37(Memory *, State *) {
  return State->gpr->rsp + 37*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_38(Memory *, State *) {
  return State->gpr->rsp + 38*4; //XXX(car) sizeof
}

addr_t __mcsema_cdecl_arg_39(Memory *, State *) {
  return State->gpr->rsp + 39*4; //XXX(car) sizeof
}

} // namespace mcsema
