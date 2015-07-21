BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_SF|FLAG_PF
;TEST_FILE_META_END

;TEST_BEGIN_RECORDING
lea ecx, [esp-0x30]
and ecx, 0xFFFFFFF0

mov dword [ecx+0x00], 0xABCDEF01
mov dword [ecx+0x04], 0xBBBBBBBB
mov dword [ecx+0x08], 0xCCCCCCCC
mov dword [ecx+0x0C], 0xDDDDDDDD
movdqu xmm0, [ecx]

mov dword [ecx+0x00], 0x0001FF1A
mov dword [ecx+0x04], 0x0aB485B1
mov dword [ecx+0x08], 0x12345678
mov dword [ecx+0x0C], 0x9abcdef0
movdqu xmm1, [ecx]

pshufb xmm0, xmm1
mov ecx, 0
;TEST_END_RECORDING

cvtsi2sd xmm0, ecx
cvtsi2sd xmm1, ecx 
