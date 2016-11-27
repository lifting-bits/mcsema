BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_PF
;TEST_FILE_META_END
    
; convert 10 to a single precision float and store in xmm0
mov ecx, 10
cvtsi2ss xmm0, ecx

;TEST_BEGIN_RECORDING
lea rcx, [rsp-0x30]
and rcx, 0xFFFFFFFFFFFFFFF0

movss [rcx], xmm0
mov DWORD [rcx+0x04], 0x0
mov DWORD [rcx+0x08], 0x0
mov DWORD [rcx+0x0C], 0x0

divps xmm0, [rcx]
mov rcx,0
;TEST_END_RECORDING

xorps xmm0, xmm0
