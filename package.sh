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
mkdir -p ${PKGDIR}/tools
mkdir -p ${PKGDIR}/runtime
mkdir -p ${PKGDIR}/defs

# ensure we always copy CFG protobuf parser
# OLD chmod +x ./build/mc-sema/bin_descend/CFG_pb2.py
chmod +x ./build/mcsema_generated/CFG_pb2.py
#MC_BINS=$(find ./build/mcsema -executable -type f | grep -v '/pin/' | grep -v 'testSemantics' | grep -v 'valTest')
MC_BINS=$(find ./bin -executable -type f)
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
cp -v ./build/llvm/bin/opt ${PKGDIR}/bin/
cp -v ./build/llvm/bin/llvm-link ${PKGDIR}/bin/
cp -v ./build/llvm/bin/llc ${PKGDIR}/bin/

echo "Packaging scripts..."
cp -vR ./mcsema/tools/* ${PKGDIR}/tools/

echo "Packaging runtime..."
cp -vR ./build/mcsema//Arch/X86/Runtime/*.a ${PKGDIR}/runtime/
cp -vR ./build/mcsema/Arch/X86/Runtime/*.{S} ${PKGDIR}/runtime 2>/dev/null

echo "Packaging export definition files"
cp -vR ./tools/mcsema_disass/defs/* ${PKGDIR}/defs/

echo "Packaging RegisterState.h"
cp -v ./mcsema/Arch/X86/Runtime/State.h ${PKGDIR}/runtime/

echo "Building .deb file..."
fpm -s dir -t deb --name mcsema --version ${VERSION} --maintainer "<mcsema@trailofbits.com>" --url "https://github.com/trailofbits/mcsema" --vendor "Trail of Bits" --prefix "/usr/local/bin" -C ./package .

echo "Building .rpm file..."
fpm -s dir -t rpm --name mcsema --version ${VERSION} --maintainer "<mcsema@trailofbits.com>" --url "https://github.com/trailofbits/mcsema" --vendor "Trail of Bits" --prefix "/usr/local/bin" -C ./package .
