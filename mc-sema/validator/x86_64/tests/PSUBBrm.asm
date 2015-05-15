BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_OF|FLAG_SF|FLAG_ZF|FLAG_AF|FLAG_PF|FLAG_CF
;TEST_FILE_META_END
 
; allocate 16 byte aligned stack space for the packed values   
lea rcx, [rsp-17]
and rcx, 0xfffffffffffffff0

; load 128 bit value into xmm0
mov DWORD [rcx], 0x12345678
mov DWORD [rcx+4], 0x55555555
mov DWORD [rcx+8], 0xdeadbeef
mov DWORD [rcx+12], 0x1f311c47
movaps xmm0, [rcx]
lea rcx, [rcx+16]

;TEST_BEGIN_RECORDING
lea rcx, [rsp-17]
and rcx, 0xfffffffffffffff0 ; using this requires us to ignore ALU flags

mov DWORD [rcx], 0xabcdef12
mov DWORD [rcx+4], 0xaaaaaaaa
mov DWORD [rcx+8], 0xdeadbeef
mov DWORD [rcx+12], 0xfeeb1e01

psubb xmm0, [rcx]
mov ecx, [rcx]
mov ecx, 0
;TEST_END_RECORDING

cvtsi2sd xmm0, ecx
