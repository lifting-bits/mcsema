BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

;TEST_BEGIN_RECORDING
lea ecx, [esp-0x10]
mov dword [ecx+0x00], 0xaabbccdd
mov dword [ecx+0x04], 0x00112233
mov dword [ecx+0x08], 0x44556677
mov dword [ecx+0x0C], 0x11223344
movdqu xmm0, [ecx]

psraw xmm0, 0x08
mov ecx, 0
;TEST_END_RECORDING

cvtsi2sd xmm0, ecx
