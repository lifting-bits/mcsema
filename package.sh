#!/bin/bash

# sudo apt-get install rpm ruby-dev
# gem install fpm

set -u

echo "This script packages mcsema into deb and rpm packages"

FPM=$(which fpm)
if [ ! -e "${FPM}" ]
then
    echo "Could not find fpm."
    echo "Please install via:"
    echo ""
    echo "$ sudo apt-get install rpm ruby-dev"
    echo "$ sudo gem install fpm"

    exit 1
fi


echo "Cleaning old directory"
PKGDIR=./package/mcsema
rm -rf ${PKGDIR}

# get a version number
GIT_HASH=$(git rev-parse --short HEAD)
GIT_DATE=$(git log -n 1 --format="%ai")
DATE=$(date --utc --date="${GIT_DATE}" +%Y%m%d%H%M)
VERSION=0.2-${DATE}-${GIT_HASH}
echo "MCSEMA Version is: ${VERSION}"

# collect the mcsema bins
mkdir -p ${PKGDIR}/bin
mkdir -p ${PKGDIR}/scripts
mkdir -p ${PKGDIR}/runtime
mkdir -p ${PKGDIR}/stddefs
mkdir -p ${PKGDIR}/drivers

# ensure we always copy CFG protobuf parser
chmod +x ./build/mc-sema/bin_descend/CFG_pb2.py
MC_BINS=$(find ./build/mc-sema -executable -type f | grep -v '/pin/' | grep -v 'testSemantics' | grep -v 'valTest')
if [ "${MC_BINS}" == "" ]
then
    echo "Could not find mcsema binaries. Did you build mcsema?"
    exit -1
fi
for BINFILE in ${MC_BINS}
do
    echo "Packaging ${BINFILE}..."
    cp ${BINFILE} ${PKGDIR}/bin/
done

echo "Packaging llvm tools"
cp -v ./build/llvm-3.5/bin/opt ${PKGDIR}/bin/
cp -v ./build/llvm-3.5/bin/llvm-link ${PKGDIR}/bin/
cp -v ./build/llvm-3.5/bin/llc ${PKGDIR}/bin/

echo "Packaging scripts..."
cp -vR ./scripts/* ${PKGDIR}/scripts/

echo "Packaging runtime..."
cp -vR ./build/mc-sema/runtime/*.bc ${PKGDIR}/runtime/
cp -vR ./build/mc-sema/runtime/*.{c,cpp} ${PKGDIR}/runtime 2>/dev/null

echo "Packaging export definition files"
cp -vR ./mc-sema/std_defs/* ${PKGDIR}/stddefs/

echo "Packaging drivers"
cp -vR ./drivers/* ${PKGDIR}/drivers/

echo "Packaging RegisterState.h"
cp -v ./mc-sema/common/RegisterState.h ${PKGDIR}/drivers/

echo "Packaging scripts"
cp -vR ./scripts/* ${PKGDIR}/scripts/

echo "Building .deb file..."
fpm -s dir -t deb --name mcsema --version ${VERSION} --maintainer "<mcsema@trailofbits.com>" --url "https://github.com/trailofbits/mcsema" --vendor "Trail of Bits" --prefix "/usr/local/bin" -C ./package .

echo "Building .rpm file..."
fpm -s dir -t rpm --name mcsema --version ${VERSION} --maintainer "<mcsema@trailofbits.com>" --url "https://github.com/trailofbits/mcsema" --vendor "Trail of Bits" --prefix "/usr/local/bin" -C ./package .
