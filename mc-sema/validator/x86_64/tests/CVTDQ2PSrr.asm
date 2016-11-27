BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; allocate 16 byte aligned stack space for the packed values
lea rcx, [rsp-0x30]
and rcx, 0xFFFFFFFFFFFFFFF0

; load a 128 bit value into xmm0
mov dword [rcx+0x00], 0xAABBCCDD
mov dword [rcx+0x04], 0xEEFF1122
mov dword [rcx+0x08], 0x33445566
mov dword [rcx+0x0C], 0x77889900
movdqu xmm1, [rcx]

;TEST_BEGIN_RECORDING
cvtdq2ps xmm0, xmm1
;TEST_END_RECORDING

mov rcx, 0
xorps xmm0, xmm0
xorps xmm1, xmm1
