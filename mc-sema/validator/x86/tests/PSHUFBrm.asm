BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_OF|FLAG_SF|FLAG_ZF|FLAG_AF|FLAG_PF|FLAG_CF
;TEST_FILE_META_END
 
; allocate 16 byte aligned stack space for the packed values   
lea ecx, [esp-17]
and ecx, 0xfffffff0

; load 128 bit value into xmm0
mov DWORD [ecx], 0xAABBCCDD
mov DWORD [ecx+4], 0xFFEEDDCC
mov DWORD [ecx+8], 0x11223344
mov DWORD [ecx+12], 0x55667788
movaps xmm0, [ecx]
lea ecx, [ecx+16]

;TEST_BEGIN_RECORDING
lea ecx, [esp-17]
and ecx, 0xfffffff0 ; using this requires us to ignore ALU flags

mov DWORD [ecx], 0xBBAA9988
mov DWORD [ecx+4], 0x77665544
mov DWORD [ecx+8], 0x33221100
mov DWORD [ecx+12], 0xABACADAE

pshufb xmm0, [ecx]
mov ecx, [ecx]
mov ecx, 0
;TEST_END_RECORDING

cvtsi2sd xmm0, ecx
