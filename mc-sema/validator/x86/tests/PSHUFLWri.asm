BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_SF|FLAG_PF
;TEST_FILE_META_END

;TEST_BEGIN_RECORDING
lea ecx, [esp-0x30]
and ecx, 0xFFFFFFF0

mov DWORD [ecx], 0xAABBCCDD
mov DWORD [ecx+4], 0xFFEEDDCC
mov DWORD [ecx+8], 0x11223344
mov DWORD [ecx+12], 0x55667788
movdqu xmm0, [ecx]

mov DWORD [ecx], 0xFFEEDDCC
mov DWORD [ecx+4], 0x77665544
mov DWORD [ecx+8], 0x99AABBCC
mov DWORD [ecx+12], 0xDDEEFF00
movdqu xmm1, [ecx]

pshuflw xmm0, xmm1, 0x1a
mov ecx, 0
;TEST_END_RECORDING

cvtsi2sd xmm0, ecx
cvtsi2sd xmm1, ecx 

