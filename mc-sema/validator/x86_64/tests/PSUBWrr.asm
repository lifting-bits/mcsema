BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; allocate 16 byte aligned stack space for the packed values
lea rcx, [rsp-33]
and rcx, 0xfffffffffffffff0

; load a 128 bit value into xmm0
mov DWORD [rcx], 0x55555555
mov DWORD [rcx+4], 0x14530451
mov DWORD [rcx+8], 0x1badb002
mov DWORD [rcx+12], 0xf0f0f0f0
movaps xmm0, [rcx]
lea rcx, [rcx+16]

; load a 128 bit value into xmm1
mov DWORD [rcx], 0xaaaaaaaa
mov DWORD [rcx+4], 0xcafebabe
mov DWORD [rcx+8], 0x2badb002
mov DWORD [rcx+12], 0x0e0e0e0e
movaps xmm1, [rcx]

;TEST_BEGIN_RECORDING
psubw xmm0, xmm1
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2sd xmm0, ecx
cvtsi2sd xmm1, ecx

