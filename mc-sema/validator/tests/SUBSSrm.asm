BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; convert 1 to a double precision float and store in xmm0
mov ecx, 1
cvtsi2ss xmm0, ecx

;TEST_BEGIN_RECORDING
; load 1.5 (in double precision float form)
lea ecx, [esp-4]
mov DWORD [ecx], 0x3fc00000

subss xmm0, [ecx]
mov ecx, [ecx]
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2sd xmm0, ecx
