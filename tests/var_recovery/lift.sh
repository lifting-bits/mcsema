#!/bin/bash

#need to:
# pip install enum34
# pip install pyelftools


MCSEMA_SRC=/store/artem/ve/git/remill
MCSEMA_DIR=/store/artem/ve

CXX=${MCSEMA_SRC}/remill-build/libraries/llvm/bin/clang++
LIFTER=${MCSEMA_DIR}/bin/mcsema-lift-4.0
ABI_DIR=${MCSEMA_SRC}/remill-build/tools/mcsema/mcsema/OS/Linux


IDA_DIR=/home/artem/ida-6.9

function binja_check
{
  echo "[+] Checking for Binary Ninja installation"
  python -c "import binaryninja" > /dev/null 2>/dev/null
  if [[ "$?" -ne 0 ]]; then
    echo "[!] Could not find binaryninja python module in your PYTHONPATH"
    echo "Did you install Binary Ninja?"
    echo "Did you set PYTHONPATH to /<binja install dir>/python ?"
    exit 1
  fi
}

function clean_check
{
  echo "Cleaning old output..."
  local in_file=${1}
  rm -rf ${OUT_DIR}/${in_file}.cfg ${OUT_DIR}/${in_file}.bc ${OUT_DIR}/${in_file}_out.txt ${OUT_DIR}/${in_file}_lifted*
}

function recover_globals_nodebug
{
	local in_file=${1}
  local outname=${OUT_DIR}/global_nodebug.protobuf

  echo "Recovering Globals (without debug info)..."
  echo "  From file: " ${IN_DIR}/${in_file}

  rm -f ${outname}
	python ${MCSEMA_SRC}/tools/mcsema/tools/mcsema_disass/ida/variable_analysis_binja.py --binary \
	  ${IN_DIR}/${in_file} \
		--out ${outname} \
		--log_file ${OUT_DIR}/global_nodebug.log --entrypoint main
}

function recover_globals_debug
{
	local in_file=${1}
  local outname=${OUT_DIR}/global_debug.protobuf

  echo "Recovering Globals (with dwarf)..."
  echo "  From file: " ${IN_DIR}/${in_file}

  rm -f ${outname}
  python ${MCSEMA_SRC}/tools/mcsema/tools/mcsema_disass/ida/var_recovery.py --binary ${IN_DIR}/${in_file} \
    --out ${outname} \
    --log_file ${OUT_DIR}/global_debug.log
}

function recover_cfg
{
	echo "Recovering CFG and Stack Variables..."
	local in_file=${1}
	${MCSEMA_DIR}/bin/mcsema-disass --disassembler ${IDA_DIR}/idal64 \
		--entrypoint main \
		--arch amd64 \
		--os linux \
		--binary ${IN_DIR}/${in_file} \
		--output ${OUT_DIR}/${in_file}.cfg \
		--log_file ${OUT_DIR}/${in_file}_out.txt \
		--recover-stack-vars \
		--recover-global-vars \
		${OUT_DIR}/global.protobuf \
		--recover-exception
}

function lift_binary
{
	echo "Lifting binary..."
	local in_file=${1}
	${LIFTER} --arch amd64 \
		--os linux \
		--cfg ${OUT_DIR}/${in_file}.cfg \
		--output ${OUT_DIR}/${in_file}.bc \
		--libc_constructor __libc_csu_init \
		--libc_destructor __libc_csu_fini \
    --abi-libraries=${ABI_DIR}/ABI_exceptions_amd64.bc \
    --disable_optimizer
}

function new_binary
{
	echo "Generating lifted binary..."
	local in_file=${1}
	${CXX} -std=c++11 -m64 -g -O0 -o ${OUT_DIR}/${in_file}-lifted \
		${OUT_DIR}/${in_file}.bc \
		-lmcsema_rt64-4.0 \
		-L${MCSEMA_DIR}/lib
}


#TODO(artem): make not linux/amd64 only
#TODO(artem): add option to run on a specific file

binja_check

for arch in amd64
do
  FILES=$(find bin/${arch}/linux/ -type f -executable )

  for input_file in ${FILES}
  do
    IN_DIR=$(dirname $(realpath ${input_file} ) )
    OUT_DIR=${IN_DIR}
    inp_file=$(basename $(realpath ${input_file} ) )

    echo "Processing ${inp_file}"
    clean_check ${inp_file}
    if [ ${inp_file: -3} == "_nd" ]
    then
      recover_globals_nodebug ${inp_file}
    elif [ ${inp_file: -6} == "_debug" ]
    then
      recover_globals_debug ${inp_file}
    else
      echo "Not sure how to recover varaibles in ${inp_file}"
      exit 1
    fi

  done

done

#recover_cfg ${IN_FILE}
#lift_binary ${IN_FILE}
#new_binary ${IN_FILE}

