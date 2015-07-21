BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_OF|FLAG_SF|FLAG_ZF|FLAG_AF|FLAG_PF|FLAG_CF
;TEST_FILE_META_END
 
; allocate 16 byte aligned stack space for the packed values   
lea ecx, [esp-17]
and ecx, 0xfffffff0

; load 128 bit value into xmm0
mov DWORD [ecx], 0x00d05602
mov DWORD [ecx+4], 0x015105a5
mov DWORD [ecx+8], 0xd1a21111
mov DWORD [ecx+12], 0xaaaaaaaa
movaps xmm0, [ecx]
lea ecx, [ecx+16]

;TEST_BEGIN_RECORDING
lea ecx, [esp-17]
and ecx, 0xfffffff0 ; using this requires us to ignore ALU flags

mov DWORD [ecx], 0xa10de002
mov DWORD [ecx+4], 0x120150aa
mov DWORD [ecx+8], 0x4ead1111
mov DWORD [ecx+12], 0xaaaaaaaa

pcmpeqw xmm0, [ecx]
mov ecx, [ecx]
xor ecx, ecx
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2sd xmm0, ecx 
