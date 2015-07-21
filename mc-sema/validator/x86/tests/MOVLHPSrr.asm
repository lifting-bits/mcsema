BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_SF|FLAG_PF
;TEST_FILE_META_END

;TEST_BEGIN_RECORDING
lea ecx, [esp-0x20]
and ecx, 0xFFFFFFF0
mov dword [ecx+0x00], 0xABCDEF00
mov dword [ecx+0x04], 0x01234567
mov dword [ecx+0x08], 0x98765431
mov dword [ecx+0x0C], 0xcabbbab5
movaps xmm0, [ecx]
mov dword [ecx+0x00], 0xf00dbad0
mov dword [ecx+0x04], 0xcafebabe
mov dword [ecx+0x08], 0x1badb0b0
mov dword [ecx+0x0C], 0xfeedbeef
movaps xmm1, [ecx]

movlhps xmm1, xmm0
mov ecx, 0
;TEST_END_RECORDING 
cvtsi2ss xmm0, ecx
cvtsi2ss xmm1, ecx

