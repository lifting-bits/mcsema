BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; convert 1 to a double precision float and store in xmm0
mov ecx, 1
cvtsi2sd xmm0, ecx

;TEST_BEGIN_RECORDING   
; load 2.5 (in double precision float form)
lea rcx, [rsp-8]
mov DWORD [rcx], 0
mov DWORD [rcx+4], 0x40040000

subsd xmm0, [rcx]
mov ecx, [rcx]
;TEST_END_RECORDING

xor ecx, ecx
cvtsi2sd xmm0, ecx
