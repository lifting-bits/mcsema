BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; put 2 into ecx for future load into xmm0
mov ecx, 2
cvtsi2ss xmm0, ecx

;TEST_BEGIN_RECORDING
cvtps2pd xmm0, xmm0
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2sd xmm0, ecx
