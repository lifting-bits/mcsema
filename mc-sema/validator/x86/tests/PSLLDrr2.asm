BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

;TEST_BEGIN_RECORDING
lea ecx, [esp-0x10]
mov dword [ecx+0x00], 0x0
mov dword [ecx+0x04], 0x0
mov dword [ecx+0x08], 0x0
mov dword [ecx+0x0C], 0xFF
;set up ecx to be 8
movdqu xmm1, [ecx]

mov dword [ecx+0x00], 0xF0FFF000
mov dword [ecx+0x04], 0xF0FFF000
mov dword [ecx+0x08], 0xF0FFF000
mov dword [ecx+0x0C], 0xF0FFF000
movdqu xmm0, [ecx]

pslld xmm0, xmm1
mov ecx, 0
;TEST_END_RECORDING

cvtsi2sd xmm0, ecx
cvtsi2sd xmm1, ecx 

