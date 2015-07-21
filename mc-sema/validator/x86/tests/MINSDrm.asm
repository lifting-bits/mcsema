BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

mov ecx, 0xABCDEF
cvtsi2sd xmm0, ecx
mov ecx, 0x012349
cvtsi2sd xmm1, ecx
;TEST_BEGIN_RECORDING
lea ecx, [esp-8]
movsd [ecx], xmm1
minsd xmm0, [ecx]
mov ecx, 0
;TEST_END_RECORDING
cvtsi2sd xmm0, ecx
cvtsi2sd xmm1, ecx


