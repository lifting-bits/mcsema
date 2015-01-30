BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; convert 3 to a double precision float and store in xmm0
mov ecx, 3
cvtsi2ss xmm0, ecx

; convert 2 to a double precision float and store in xmm1
mov ecx, 2
cvtsi2ss xmm1, ecx

;TEST_BEGIN_RECORDING
divss xmm0, xmm1
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2sd xmm0, ecx
cvtsi2sd xmm1, ecx
