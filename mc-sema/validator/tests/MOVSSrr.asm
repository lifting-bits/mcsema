BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; convert 1 to a single precision float and store in xmm0
mov ecx, 0
cvtsi2ss xmm0, ecx
mov ecx, 0xFFFFFFFF
cvtsi2ss xmm2, ecx
mov ecx, 0
cvtsi2ss xmm3, ecx

; convert 2 to a single precision float and store in xmm1
mov ecx, 2
cvtsi2ss xmm1, ecx

;TEST_BEGIN_RECORDING
movss xmm0, xmm1
movss xmm2, xmm1
movss xmm3, xmm1
;TEST_END_RECORDING 
xor ecx, ecx
cvtsi2ss xmm0, ecx
cvtsi2ss xmm1, ecx
cvtsi2ss xmm3, ecx
