BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; put 2 into ecx for future load into xmm0
mov ecx, 2
cvtsi2ss xmm0, ecx
mov ecx, 0
cvtsi2ss xmm1, ecx

;TEST_BEGIN_RECORDING
ucomiss xmm0, xmm1
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2ss xmm0, ecx
cvtsi2ss xmm1, ecx
