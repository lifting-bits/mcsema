BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_OF|FLAG_SF|FLAG_ZF|FLAG_AF|FLAG_PF|FLAG_CF
;TEST_FILE_META_END

;TEST_BEGIN_RECORDING
; allocate 16 byte aligned stack space for the packed values
lea rcx, [rsp-0x30]
and rcx, 0xFFFFFFFFFFFFFFF0

; load a 64 bit value into mem
mov dword [rcx+0x00], 0xAABBCCDD
mov dword [rcx+0x04], 0xEEFF1122

movhpd xmm0, [rcx]
mov rcx, 0
;TEST_END_RECORDING

cvtsi2sd xmm0, ecx
