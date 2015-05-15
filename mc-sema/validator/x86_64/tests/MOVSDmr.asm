BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    
; convert 0xbadf00d to a double precision float and store in xmm0
mov ecx, 0xbadf00d
cvtsi2sd xmm0, ecx

;TEST_BEGIN_RECORDING
; load badf00d (in double precision float form)
lea rcx, [rsp-8]
movsd [rcx], xmm0

mov eax, [rcx+0]
mov ebx, [rcx+4]
mov rcx, 0
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2sd xmm0, ecx
