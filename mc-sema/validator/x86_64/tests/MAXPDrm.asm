BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_OF|FLAG_SF|FLAG_ZF|FLAG_AF|FLAG_PF|FLAG_CF
;TEST_FILE_META_END

;TEST_BEGIN_RECORDING
; allocate 16 byte aligned stack space for the packed values
lea rcx, [rsp-0x30]
and rcx, 0xFFFFFFFFFFFFFFF0

; load a 128 bit value into xmm0
mov dword [rcx+0x00], 0xAABBCCDD
mov dword [rcx+0x04], 0xEEFF1122
mov dword [rcx+0x08], 0x33445566
mov dword [rcx+0x0C], 0x77889900
movdqu xmm0, [rcx]

lea rcx, [rcx+16]
mov DWORD [rcx], 0xaaaaaaaa
mov DWORD [rcx+4], 0xcafebabe
mov DWORD [rcx+8], 0x2badb002
mov DWORD [rcx+12], 0x0e0e0e0e

maxpd xmm0, [rcx]
mov rcx, 0
;TEST_END_RECORDING

cvtsi2sd xmm0, ecx
cvtsi2sd xmm1, ecx
