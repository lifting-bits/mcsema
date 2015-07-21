BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; allocate 16 byte aligned stack space for the packed values
lea ecx, [esp-33]
and ecx, 0xfffffff0

; load a 128 bit value into xmm1
mov DWORD [ecx], 0x8e1efe2e
mov DWORD [ecx+4], 0x00adb002
mov DWORD [ecx+8], 0x00adb002
mov DWORD [ecx+12], 0x8e1efe2e
movaps xmm1, [ecx]

;TEST_BEGIN_RECORDING
pmovzxbd xmm0, xmm1
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2sd xmm0, ecx
cvtsi2sd xmm1, ecx

