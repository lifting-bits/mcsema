#!/bin/bash

sanity_check() {
    if [ ! -e "${WHICHBIN}" ]
    then
        echo "Could not find binary to translate: ${WHICHBIN}"
        exit 1
    fi

    if [ ! -e "${IDA}" ]
    then
        echo "Could not find IDA at ${IDA}."
        exit 1
    fi

    if [ ! -e "${CFG_TO_BC_PATH}/cfg_to_bc" ]
    then
        echo "Could not find cfg_to_bc (looked for: ${CFG_TO_BC_PATH}/cfg_to_bc)."
        echo "Are you running this script from the installation directory of an installed mcsema package?" 
        echo "e.g. (/usr/local/bin/mcsema/scripts). It wont work from the development directory"
        exit 1
    fi

    COMP=$(which ${CC})
    if [ ! -e "${COMP}" ]
    then
        echo "Could not find a C compiler. Looked for ${CC}"
        exit 1
    fi
}

recover_cfg () {
    if [ -e "${IDA}" ]
    then
        echo "Recovering CFG to: ${2}"
        ${IDA} -B -S"${GET_CFG_PY} --batch  --std-defs=${STD_DEFS}/linux.txt --std-defs=${STD_DEFS}/apr_defs.txt --std-defs=${STD_DEFS}/pcre_defs.txt --entry-symbol main --output=${2}" ${1} >> /dev/null
    else
        echo "Could not find IDA at ${IDA}"
        exit 1
    fi
    if [ ! -e "${2}" ]
    then
        echo "Could not find output CFG (${2}). Assuming CFG recovery failed"
        exit 1
    fi
}


convert_to_bc() {
    echo "Converting cfg => bc (${2})"
    ${CFG_TO_BC_PATH}/cfg_to_bc -post-analysis=false -mtriple=x86_64-pc-linux-gnu -i ${1} -driver=mcsema_main,main,raw,return,C -o ${2} >> ${IDALOG} 2> ${WORKSPACE}/xlate_errors.log
}

optimize_bc() {
    echo "Optimizing... (${2})"
    ${LLVM_PATH}/opt -O3 -o ${2} ${1}
}

link_amd64_callback() {
    echo "Linking in amd64 mcsema runtime support... (${2})"
    ${LLVM_PATH}/llvm-link ${RUNTIME_PATH}/linux_amd64_callback.bc ${1} > ${2}
}

call_llc() {
    echo "Converting bitcode to native code... (${2})"
    ${LLVM_PATH}/llc -filetype=obj -o ${2} ${1}
}

