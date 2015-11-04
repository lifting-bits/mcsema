BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_SF|FLAG_PF
;TEST_FILE_META_END

;TEST_BEGIN_RECORDING
lea rcx, [rsp-0x30]
and rcx, 0xFFFFFFFFFFFFFFF0

mov dword [rcx+0x00], 0xAABBCCDD
mov dword [rcx+0x04], 0xEEFF1122
mov dword [rcx+0x08], 0x33445566
mov dword [rcx+0x0C], 0x77889900
movdqu xmm0, [rcx]
mov dword [rcx+0x00], 0x00112233
mov dword [rcx+0x04], 0x44556677
mov dword [rcx+0x08], 0x8899AABB
mov dword [rcx+0x0C], 0xCCDDEEFF
movdqu xmm1, [rcx]

unpcklps xmm0, xmm1
mov ecx, 0
;TEST_END_RECORDING

cvtsi2sd xmm0, ecx
cvtsi2sd xmm1, ecx 
