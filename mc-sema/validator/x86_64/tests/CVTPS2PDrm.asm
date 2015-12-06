BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

mov ecx, 2
cvtsi2ss xmm0, ecx

mov rax, rsp
sub rax, 16
and rax, -16
xchg rax, rsp
movaps [rsp], xmm0

;TEST_BEGIN_RECORDING
cvtps2pd xmm0, xmm0
;TEST_END_RECORDING

xchg rax, rsp
xor ecx, ecx
xor eax, eax
cvtsi2sd xmm0, ecx
