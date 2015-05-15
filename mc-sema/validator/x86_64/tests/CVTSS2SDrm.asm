BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

;TEST_BEGIN_RECORDING
lea rcx, [rsp-4]
mov DWORD [rcx], 0x3fc00000

cvtss2sd xmm0, [rcx]

mov ecx, [rcx]
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2sd xmm0, ecx
