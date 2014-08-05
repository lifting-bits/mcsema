# Adding a New Test

This section describes how to add a new unit test for instruction semantics. The examplar instruction will be `FSIN`, since it was previously added in the "Addin a New Instruction" section.

## Files Involved

All instruction tests are located in `mc-sema/validator/tests`. The tests are assembly files with a special name and header. 

The name of the file, such as `XADD8rr.asm` specifies the instruction being tested. This is the LLVM name for the opcode. In this instance, we will be adding `FSIN.asm`. The file may already be present, if it is, pretend it doesn't exist.

All files in this directory are automatically added to the test suite. No changes, other than placing a file with the appropriate name in this directory are required.


## Test Headers.

First, lets create a file named `FSIN.asm`. This file, like all other tests, needs to start with a special header:

	BITS 32
	;TEST_FILE_META_BEGIN
	;TEST_TYPE=TEST_F
	;TEST_IGNOREFLAGS=FLAG_FPU_C1|FLAG_FPU_PE
	;TEST_FILE_META_END

Each value of the header has a meaning:

* `BITS 32`: Needed by `nasm` to treat this as 32-bit assembly
* `TEST_FILE_META_BEGIN`: A token indiating the start of test metadata
* `TEST_TYPE`: The type of test that will be run. The only valid option is `TEST_F`.
* `TEST_IGNOREFLAGS`: Which flags this test should ignore when determining success or failure. Some instructions leave flags in an undefined state. If so, these should be listed here.

Valid flags are:

* `FLAG_CF`
* `FLAG_PF`
* `FLAG_AF`
* `FLAG_ZF`
* `FLAG_SF`
* `FLAG_OF`
* `FLAG_DF`
* `FLAG_FPU_BUSY`
* `FLAG_FPU_C3`
* `FLAG_FPU_TOP`
* `FLAG_FPU_C2`
* `FLAG_FPU_C1`
* `FLAG_FPU_C0`
* `FLAG_FPU_ES`
* `FLAG_FPU_SF`
* `FLAG_FPU_PE`
* `FLAG_FPU_UE`
* `FLAG_FPU_OE`
* `FLAG_FPU_ZE`
* `FLAG_FPU_DE`
* `FLAG_FPU_IE`

When more than one flag should be ignored, flags must be combined with the bitwise-OR operator `|`. For example, to ignore both AF and CF, the ignoreflags line would be `;TEST_IGNOREFLAGS=FLAG_AF|FLAG_CF`.

* `TEST_FILE_META_END`: A token indicating the end of test metadata

In this particular example, `FLAG_FPU_C1` and `FLAG_FPU_PE` are ignored. These flags indicate an FPU stack underflow and precision error, respectively. They are both ignored because they are artifacts of incomplete precision control support.

## Test Instructions

Now, lets add the actual instructions under test to `FSIN.asm`:

	; set up st0 to be PI/2
	FLDPI
	LEA ESI, [ESP-08]
	MOV word [ESI], 0x2
	FIDIV word [ESI]
	
	;TEST_BEGIN_RECORDING
	FSIN
	;TEST_END_RECORDING

The lines beginning with `;` are comments. 

Everything before the line `;TEST_BEGIN_RECORDING` is used to set up the original test environment. The actions of these instructions will be captured to create a beginning register state. This is useful for instructions such as `FSIN` that operate on a specific register. In this specific example, we load PI/2 into `st0`, since sin(pi/2) = 1.0, and is easy to verify.

Everything after `;TEST_BEGIN_RECORDING` but before `;TEST_END_RECORDING` will affect register state that is compared against ground truth. In this case only the `FSIN` instruction is executed.

Any code after `;TEST_END_RECORDING` should serve as cleanup code or code necessary to ensure nothing crashes in case of critical state modifictions. Usually this will be blank.


## Final Test File

The final `FSIN.asm` should look like:

	BITS 32
	;TEST_FILE_META_BEGIN
	;TEST_TYPE=TEST_F
	;TEST_IGNOREFLAGS=FLAG_FPU_C1|FLAG_FPU_PE
	;TEST_FILE_META_END
	
	; set up st0 to be PI/2
	FLDPI
	LEA ESI, [ESP-08]
	MOV word [ESI], 0x2
	FIDIV word [ESI]
	
	;TEST_BEGIN_RECORDING
	FSIN
	;TEST_END_RECORDING

## Running the Tests

To run the unit tests, see the documentation for `testSemantics.exe` in the [TOOLS.md](TOOLS.md) document.. After adding a new test file, the `mc-sema` project will need to be re-built to regenarate ground truth and new unit tests.
