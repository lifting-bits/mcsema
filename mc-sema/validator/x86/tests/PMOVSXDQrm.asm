BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_OF|FLAG_SF|FLAG_ZF|FLAG_AF|FLAG_PF|FLAG_CF
;TEST_FILE_META_END
 
; allocate 16 byte aligned stack space for the packed values   
;TEST_BEGIN_RECORDING
lea ecx, [esp-0x20]
and ecx, 0xfffffff0

; load 128 bit value into xmm0
mov DWORD [ecx], 0x82345678
mov DWORD [ecx+4], 0x155785f5
mov DWORD [ecx+8], 0xdeadbeef
mov DWORD [ecx+12], 0x1f311c47

pmovsxdq xmm0, [ecx]
mov ecx, 0
;TEST_END_RECORDING

cvtsi2sd xmm0, ecx
