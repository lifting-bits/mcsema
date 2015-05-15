BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; set up st0 to be 1.0
FLD1
;TEST_BEGIN_RECORDING
lea rdi, [rsp-08]
; 3.1415926 or there about
mov dword [rdi+00], 0x54442d18
mov dword [rdi+04], 0x400921fb
FSUBR qword [rdi]
mov edi, 0
;TEST_END_RECORDING
