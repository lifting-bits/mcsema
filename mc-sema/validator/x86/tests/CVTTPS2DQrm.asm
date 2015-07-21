BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_SF|FLAG_PF
;TEST_FILE_META_END

mov ecx, 0
;TEST_BEGIN_RECORDING
lea ecx, [esp-0x20]
and ecx, 0xFFFFFFF0
mov dword [ecx+0x0], 0x023490
mov dword [ecx+0x4], 0x023490
mov dword [ecx+0x8], 0x033490
mov dword [ecx+0xc], 0x000010
cvttps2dq xmm1, [ecx]
mov ecx, 0
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2ss xmm0, ecx
