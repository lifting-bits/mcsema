BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; put 2 into ecx for future load into xmm0
mov ecx, 2
cvtsi2ss xmm0, ecx

;TEST_BEGIN_RECORDING
lea rcx, [rsp-8]
movss [rcx], xmm0
cvttss2si ecx, [rcx]
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2ss xmm0, ecx
