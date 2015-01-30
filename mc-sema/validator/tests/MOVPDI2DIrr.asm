BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; put 2 into ecx for future load into xmm0
mov ecx, 2
MOVD xmm0, ecx
mov ecx, 0

;TEST_BEGIN_RECORDING
MOVD eax, xmm0
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2sd xmm0, ecx
