BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

; set up st0 to be 3.141593
lea rdi, [rsp-0x8]
mov qword [rdi], 0x40490fdb
fld qword [rdi]
;TEST_BEGIN_RECORDING
lea rdi, [rsp-0x8]
mov qword [rdi], 0x40490fdb
FADD qword [rdi]
mov rdi, 0
;TEST_END_RECORDING

