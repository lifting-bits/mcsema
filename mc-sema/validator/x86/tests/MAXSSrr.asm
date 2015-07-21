BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

mov ecx, 40
cvtsi2ss xmm0, ecx
mov ecx, 10
cvtsi2ss xmm1, ecx

;TEST_BEGIN_RECORDING
maxss xmm0, xmm1
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2ss xmm0, ecx
cvtsi2ss xmm1, ecx
