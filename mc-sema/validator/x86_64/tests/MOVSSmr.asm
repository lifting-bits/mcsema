BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    
; convert 1 to a single precision float and store in xmm0
mov ecx, 1
cvtsi2ss xmm0, ecx

;TEST_BEGIN_RECORDING
; load 1 in single floating point form
lea rcx, [rsp-8]
movss [rcx], xmm0

; value should appear in eax for testing
mov rax, [rcx]
mov ecx, 0
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2ss xmm0, ecx
cvtsi2ss xmm1, ecx
