BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

mov eax, 2

;TEST_BEGIN_RECORDING
lea rcx, [rsp-4]
mov [rcx], eax
movd xmm0, [rcx]
mov ecx, 0
;TEST_END_RECORDING

cvtsi2sd xmm0, ecx
