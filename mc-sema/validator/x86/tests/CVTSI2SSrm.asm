BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; put 2 into eax for future load into xmm0
mov eax, 2

;TEST_BEGIN_RECORDING
lea ecx, [esp-4]
mov [ecx], eax
cvtsi2ss xmm0, [ecx]
mov ecx, 0
;TEST_END_RECORDING

cvtsi2sd xmm0, ecx
