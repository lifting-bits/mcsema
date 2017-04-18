CC=clang-3.8
# adapted from:
# http://stackoverflow.com/questions/18136918/how-to-get-current-relative-directory-of-your-makefile
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(dir $(mkfile_path))

OUTPUT_GEN=$(current_dir)/generate_expected_output.py

ifdef MCSEMA_PATH
	DISASS=$(MCSEMA_PATH)/mcsema-disass
else
	DISASS=$(current_dir)/../../bin/mcsema-disass
endif

ifdef IDA_PATH
	IDA32=$(IDA_PATH)/idal
	IDA64=$(IDA_PATH)/idal64
else
	IDA32=~/ida-6.9/idal
	IDA64=~/ida-6.9/idal64
endif

INTEL_SRCS=$(wildcard x86_*.c)
ALL_SRCS=$(wildcard all_*.c) 
ARM_SRCS=$(wildcard arm_*.c)

X86=$(addprefix x86/, $(patsubst x86_%,%,$(INTEL_SRCS:.c=.elf))) $(addprefix x86/, $(patsubst all_%,%,$(ALL_SRCS:.c=.elf)))
X64=$(addprefix amd64/,$(patsubst x86_%,%,$(INTEL_SRCS:.c=.elf))) $(addprefix amd64/, $(patsubst all_%,%,$(ALL_SRCS:.c=.elf)))
AARCH64=$(addprefix aarch64/,$(patsubst arm_%,%,$(ARM_SRCS:.c=.elf))) $(addprefix aarch64/, $(patsubst all_%,%,$(ALL_SRCS:.c=.elf)))

X86_CFGS=$(X86:.elf=.cfg)
X64_CFGS=$(X64:.elf=.cfg)
AARCH64_CFGS=$(AARCH64:.elf=.cfg)

X86_ELFS=$(wildcard x86/*.elf)
X64_ELFS=$(wildcard amd64/*.elf)
AARCH64_ELFS=$(wildcard aarch64/*.elf)

X86_ELFS_CFGS=$(X86_ELFS:.elf=.cfg)
X64_ELFS_CFGS=$(X64_ELFS:.elf=.cfg)
AARCH64_ELFS_CFGS=$(AARCH64_ELFS:.elf=.cfg)

.PHONY: all clean

# do not delete intermediate targets
# we may want to examine these manually
.PRECIOUS: x86/%.elf amd64/%.elf

all: outputs_amd64 outputs_x86 outputs_aarch64

# Build an ELF from our source
x86/%.elf: x86_%.c
	${CC} -maes -m32 -o $@ $<

amd64/%.elf: x86_%.c
	${CC} -maes -m64 -o $@ $<

x86/%.elf: all_%.c
	${CC} -maes -m32 -o $@ $<

amd64/%.elf: all_%.c
	${CC} -maes -m64 -o $@ $<

aarch64/%.elf: all_%.c
	${CC} -B/usr/aarch64-linux-gnu/bin/ --target=aarch64-arm-linux-gnu  -o $@ $<

aarch64/%.elf: arm_%.c
	${CC} -B/usr/aarch64-linux-gnu/bin/ --target=aarch64-arm-linux-gnu  -o $@ $<

# Translate ELFs to CFG
x86/%.cfg: x86/%.elf
	${DISASS} --disassembler ${IDA32} --arch x86 --os linux --output $@ --binary $< --entrypoint main

amd64/%.cfg: amd64/%.elf
	${DISASS} --disassembler ${IDA64} --arch amd64 --os linux --output $@ --binary $< --entrypoint main

outputs_amd64: amd64/config.json $(X64_CFGS) $(X64_ELFS_CFGS)
	$(OUTPUT_GEN) amd64/config.json amd64/expected_outputs.json

outputs_x86: x86/config.json $(X86_CFGS) $(X86_ELFS_CFGS)
	$(OUTPUT_GEN) x86/config.json x86/expected_outputs.json

#TODO(artem): For now only generate ELFs, add CFGs once CFG recovery works
outputs_aarch64: $(AARCH64)

clean:
	rm -f $(X86)
	rm -f $(X86_CFGS)
	rm -f $(X64)
	rm -f $(X64_CFGS)
	rm -f $(AARCH64)
	rm -f $(AARCH64_CFGS)
	rm -f $(X64_ELFS_CFGS)
	rm -f $(X86_ELFS_CFGS)
	rm -f $(AARCH64_ELFS_CFGS)
	rm -f amd64/expected_outputs.json
	rm -f x86/expected_outputs.json
	rm -f aarch64/expected_outputs.json
