import sys
import collections
import itertools
import os
import glob
import subprocess
import tempfile
import re
import argparse

#for debugging, use the pretty-printer
import pprint


argparser = argparse.ArgumentParser()
argparser.add_argument('-tstmpl', type=argparse.FileType('rb', 0), help="testSemantics template", required=True)
argparser.add_argument('-taout', type=argparse.FileType('wb', 0), help="assembly output for PIN", required=False)
argparser.add_argument('-tsout', type=argparse.FileType('wb', 0), help="testSemantics.cpp output", required=False)
argparser.add_argument('-testfiles', help="directory containing test files", required=True)
argparser.add_argument('-nasm', help="path to nasm executable", required=True)

args = argparser.parse_args()

if not (args.taout or args.tsout):
    sys.stderr.write("Either -taout or -tsout is required!\n")
    sys.exit(-1)

#TEST_FILES_PATH = os.path.join("..","validator", "valTest", "tests")
#NASM_PATH = os.path.join("..","validator","valTest", "nasm", "nasm.exe")

EXPECTED_LINES = ["BITS 64", ";TEST_FILE_META_BEGIN"]
META_END_MARKER = ";TEST_FILE_META_END"


TEST_NUMBER = 0x300

PREPARED_TESTS = collections.OrderedDict()

#OUTPUT_TESTSEMANTICS = "testSemantics.auto.cpp"
#OUTPUT_TEST_ASM = "test_a.auto.asm"
BEGIN_RECORDING_TOKEN = ";TEST_BEGIN_RECORDING"
END_RECORDING_TOKEN = ";TEST_END_RECORDING"
RCONST = 0x18230000
RECORDED_ASM_RE = re.compile(";TEST_(BEGIN|END)_RECORDING")


TEST_DECLARATION = """
NEW_TEST("{test_name}",   {test_number:#x});
"""

TEST_IGNOREFLAGS_DECLARATION = """
NEW_TEST_IGNOREFLAGS("{test_name}", {test_number:#x}, {test_ignoreflags});
"""

TEST_DEFINITION = """
{test_type}(ModuleTest, {test_name}) {{
    uint8_t byteArr[] = {{ {test_bytes} }};
    IN_OUT_TEST("{test_name}", byteArr);
}}
"""

def compile_asm(test_name, test_file):
    tmphandle_bin,tmpfile_bin = tempfile.mkstemp(suffix=".bin")
    tmphandle_asm,tmpfile_asm = tempfile.mkstemp(suffix=".asm")
    os.close(tmphandle_bin)
    os.close(tmphandle_asm)

    orig_asm = open(test_file, 'rb').read()
    # get only the asm between ;TEST_BEGIN_RECORDING and ;TEST_END_RECORDING
    orig_parts = RECORDED_ASM_RE.split(orig_asm)
    semantics_asm = orig_parts[2]

    #save it to a separate file for compilation
    with open(tmpfile_asm, 'wb') as asmfile:
        asmfile.write("BITS 64\n")
        asmfile.write(semantics_asm)

    try:
        subprocess.check_call([args.nasm, "-f", "bin", "-o", tmpfile_bin, tmpfile_asm])
    except subprocess.CalledProcessError as e:
        sys.stderr.write("Could not assemble test {}, original source file: {}\n".format(test_name, test_file))
        sys.stderr.write("Error was: {}\n".format(e))
        os.unlink(tmpfile_bin)
        os.unlink(tmpfile_asm)
        sys.exit(-1)


    with open(tmpfile_bin, 'rb') as binfile:
        bindata = binfile.read()

    #clean up tmpfiles
    os.unlink(tmpfile_bin)
    os.unlink(tmpfile_asm)

    # transform to c-style hex (0x##)
    bindata = ", ".join([hex(ord(x)) for x in bindata])
        
    return bindata

def parse_metadata(test_name, test_file):
    global EXPECTED_LINES

    meta_values = {}

    lines = open(test_file, 'r').readlines()
    lines = [l.strip() for l in lines]

    # do a quick sanity check on ASM files in the directory
    for i in range(2):
        if lines[i].upper() != EXPECTED_LINES[i]:
            sys.stderr.write("Failed to parse {}. Looking for {}, got {}\n".format(test_file, EXPECTED_LINES[i], lines[i] ))
            sys.exit(-1)

    #parse metadata; it should be in the form of
    #;KEY=VALUE
    # the keys are lowercased and values are uppercased
    for i in xrange(2, len(lines)-2):
        if lines[i] == META_END_MARKER:
            break
   
        try:
            vname, vval = lines[i].split('=')
            vname = vname[1:]
        except:
            sys.stderr.write("Could not parse {}; line: {}.\nExpected KEY=VALUE\n".format(test_file, lines[i]))
            sys.exit(-1)

        meta_values[vname.lower()] = vval.upper()

    #get the asm that will go into the automatically
    # generated test_a.auto.asm. That file is by PIN
    # to generate ground truth for semantics tests

    all_but_bits_line = "\n".join(lines[1:])
    all_but_bits_line = all_but_bits_line.replace(
            BEGIN_RECORDING_TOKEN, "mov rsi, {:#x}".format(RCONST+TEST_NUMBER))
    all_but_bits_line = all_but_bits_line.replace(
            END_RECORDING_TOKEN, "mov rsi, {:#x}".format(RCONST+TEST_NUMBER))

    meta_values['test_asm'] = all_but_bits_line

    return meta_values


def prepare_from_file(test_name, test_file):

    #read metadata
    meta_dict = parse_metadata(test_name, test_file)
    #get the hex bytes that go into testSemantics.auto.cpp
    hexbytes = compile_asm(test_name, test_file)
    meta_dict['test_bytes'] = hexbytes

    # see if we are using an ignoreflags or a normal declaration
    # this is determined by the value of TEST_IGNOREFLAGS metadata entry
    if meta_dict['test_ignoreflags'] == "":
        meta_dict['test_declaration'] = TEST_DECLARATION
    else:
        meta_dict['test_declaration'] = TEST_IGNOREFLAGS_DECLARATION

    return meta_dict

def prepare_tests():
    global TEST_NUMBER

    # assume every .asm file in the tests directory is a test
    #asm_files = [os.path.join(args.testfiles, "LEA16r.asm")]
    asm_files = glob.glob( os.path.join(args.testfiles,"*.asm") )
    
    # test names are the file name without .asm
    test_names = map(lambda x: os.path.basename(x)[:-4], asm_files)

    sys.stderr.write( "Found {} tests:\n".format(len(test_names)) ) 
    pprint.pprint(test_names, stream=sys.stderr)
    
    # fill out the test dictionary with a test name and an increasing
    # test number. Should be filled out in alphabetical order, or
    # whichever way glob.glob() returns files
    for test,testfile in zip(sorted(test_names), sorted(asm_files)):
        sys.stderr.write("processing: {}\n".format(test))
        PREPARED_TESTS[test] = {}
        td = PREPARED_TESTS[test]
        td['test_number'] = TEST_NUMBER
        td['test_name'] = test
        # fill out:
        #   test_bytes
        #   test_declaration
        #   test_type
        td.update(prepare_from_file(test, testfile))

        TEST_NUMBER += 1

def gen_declarations():
    declarations = ""
    for test in PREPARED_TESTS.itervalues():
        declarations += test['test_declaration'].format(**test)
                
    return declarations

def gen_definitions():
    declarations = ""
    for test in PREPARED_TESTS.itervalues():
        declarations += TEST_DEFINITION.format(**test)
                
    return declarations

def gen_asm():
    asm = ""

    for tname,test in PREPARED_TESTS.iteritems():
        asm += """\n"""
        asm += "    ;TEST: " + tname + "\n"
        asm += "    " + test['test_asm'] + "\n"

        asm += """
    ; pre-test clear to zeros
    mov  rax, 0
    mov  rcx, 0
    mov  rdx, 0
    mov  rbx, 0
    mov  rsi, 0
    mov  rdi, 0

    ; end pre-test clear
    ; restore stack
    mov  rsp, qword [internal_saveregs+0x20]
    mov  rbp, qword [internal_saveregs+0x28]
    ; add some stack slack
    sub rsp, 0x200
    mov rax, qword [internal_saveregs+0x40]
    push rax
    POPF
    FLDZ ;ST0
    FLDZ ;ST1
    FLDZ ;ST2
    FLDZ ;ST3
    FLDZ ;ST4
    FLDZ ;ST5
    FLDZ ;ST6
    FLDZ ;ST7
    FNINIT
    """

    return asm

if __name__ == "__main__":
    prepare_tests()
    decs = "// Begin Declarations\n"
    decs += gen_declarations()
    decs += "// End Declarations\n"

    defs = "// Begin Definitions\n"
    defs += gen_definitions()
    defs += "// End Definitions\n"

    data = None

    # create test_a.auto.asm
    test_asm = ""
    
    # osx needs a to change relative addressing and an extra _ for the symbol name to keep nasm happy
    if sys.platform == 'darwin':
        test_asm += """BITS 64
DEFAULT REL
section .text

global _doTest
_doTest:"""

    else:
        test_asm = """BITS 64
section .text

global doTest
doTest:"""

    test_asm += """
mov qword [internal_saveregs+0x00], rax
mov qword [internal_saveregs+0x08], rcx
mov qword [internal_saveregs+0x10], rdx
mov qword [internal_saveregs+0x18], rbx
mov qword [internal_saveregs+0x20], rsp
mov qword [internal_saveregs+0x28], rbp
mov qword [internal_saveregs+0x30], rsi
mov qword [internal_saveregs+0x38], rdi
push rax
PUSHF 
pop rax
mov qword [internal_saveregs+0x40], rax
pop rax
FNSAVE [internal_savefpu_precall]

    mov  rax, 0
    mov  rcx, 0
    mov  rdx, 0
    mov  rbx, 0
    mov  rsi, 0
    mov  rdi, 0

    sub rsp, 0x200
    mov rax, qword [internal_saveregs+0x40]
    push rax
    POPF
    FLDZ ;ST0
    FLDZ ;ST1
    FLDZ ;ST2
    FLDZ ;ST3
    FLDZ ;ST4
    FLDZ ;ST5
    FLDZ ;ST6
    FLDZ ;ST7
    FNINIT
"""
    test_asm += gen_asm()
    test_asm += """
mov  rax, qword [internal_saveregs+0x00]
mov  rcx, qword [internal_saveregs+0x08]
mov  rdx, qword [internal_saveregs+0x10]
mov  rbx, qword [internal_saveregs+0x18]
mov  rsp, qword [internal_saveregs+0x20]
mov  rbp, qword [internal_saveregs+0x28]
mov  rsi, qword [internal_saveregs+0x30]
mov  rdi, qword [internal_saveregs+0x38]
push qword [internal_saveregs+0x40]
POPF
FRSTOR [internal_savefpu_precall]
RET

SECTION .bss
internal_saveregs: RESD 10
internal_savefpu: RESB 108
internal_savefpu_precall: RESB 108
"""

    # populate testSemantics.auto.cpp
    data = args.tstmpl.read()
    args.tstmpl.close()
    data = data.replace(r'/*%DECLARATIONS*%/', decs)
    data = data.replace(r'/*%DEFINITIONS%*/', defs)
        
    if data == None:
        sys.stderr.write("Error: Could not open template file: {}\n".format(TEMPLATE_FILE))
        sys.exit(-1)
    else:
        
	if args.tsout:
            args.tsout.write(data)
            args.tsout.close()

        if args.taout:
            args.taout.write(test_asm)
            args.taout.close()


