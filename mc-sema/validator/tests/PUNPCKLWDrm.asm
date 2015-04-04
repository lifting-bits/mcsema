BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_SF|FLAG_PF
;TEST_FILE_META_END

;TEST_BEGIN_RECORDING
lea ecx, [esp-0x30]
and ecx, 0xFFFFFFF0

mov dword [ecx+0x00], 0xAABBCCDD
mov dword [ecx+0x04], 0xEEFF1122
mov dword [ecx+0x08], 0x33445566
mov dword [ecx+0x0C], 0x77889900
movdqu xmm0, [ecx]
mov dword [ecx+0x00], 0x00112233
mov dword [ecx+0x04], 0x44556677
mov dword [ecx+0x08], 0x8899AABB
mov dword [ecx+0x0C], 0xCCDDEEFF

punpcklwd xmm0, [ecx]
mov ecx, 0
;TEST_END_RECORDING

cvtsi2sd xmm0, ecx
cvtsi2sd xmm1, ecx 
