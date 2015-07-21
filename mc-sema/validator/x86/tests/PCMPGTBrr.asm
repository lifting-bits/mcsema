BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; allocate 16 byte aligned stack space for the packed values
lea ecx, [esp-33]
and ecx, 0xfffffff0

; load a 128 bit value into xmm0
mov DWORD [ecx], 0x01230415
mov DWORD [ecx+4], 0xa0a31011
mov DWORD [ecx+8], 0x1b11b10a
mov DWORD [ecx+12], 0x24f832f0
movaps xmm0, [ecx]
lea ecx, [ecx+16]

; load a 128 bit value into xmm1
mov DWORD [ecx], 0xaabacada
mov DWORD [ecx+4], 0x0afe0a0e
mov DWORD [ecx+8], 0x24adb012
mov DWORD [ecx+12], 0x0e1e0e0e
movaps xmm1, [ecx]

;TEST_BEGIN_RECORDING
pcmpgtb xmm0, xmm1
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2sd xmm0, ecx
cvtsi2sd xmm1, ecx
