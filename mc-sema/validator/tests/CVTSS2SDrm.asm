BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

;TEST_BEGIN_RECORDING
lea ecx, [esp-4]
mov DWORD [ecx], 0x3fc00000

cvtss2sd xmm0, [ecx]

mov ecx, [ecx]
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2sd xmm0, ecx
