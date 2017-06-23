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
PKGDIR=./package
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
cp -vR ./tools/* ${PKGDIR}/tools/

echo "Packaging runtime..."
cp -vR ./build/mcsema//Arch/X86/Runtime/*.a ${PKGDIR}/runtime/
cp -vR ./build/mcsema/Arch/X86/Runtime/*.{S} ${PKGDIR}/runtime 2>/dev/null

echo "Packaging export definition files"
cp -vR ./tools/mcsema_disass/defs/* ${PKGDIR}/defs/

echo "Packaging RegisterState.h"
cp -v ./mcsema/Arch/X86/Runtime/State.h ${PKGDIR}/runtime/

./bootstrap.sh --prefix ${PKGDIR}
echo "Package python libraries"
mkdir -p ${PKGDIR}/lib/python2.7/dist-packages/
cp -vR ${HOME}/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg ${PKGDIR}/lib/python2.7/dist-packages/

if [ -f /usr/local/lib/python2.7/dist-packages/google/__init__.py ]; then
    cp -vR /usr/local/lib/python2.7/dist-packages/google ${PKGDIR}/lib/python2.7/dist-packages/
fi
if [ -f /usr/lib/python2.7/dist-packages/google/__init__.py ]; then
    cp -vR /usr/lib/python2.7/dist-packages/google ${PKGDIR}/lib/python2.7/dist-packages/
fi

echo "Building .deb file..."
fpm -s dir -t deb --name mcsema --version ${VERSION} --maintainer "<mcsema@trailofbits.com>" --url "https://github.com/trailofbits/mcsema" --vendor "Trail of Bits" --prefix "/usr/local" -C ./package .

echo "Building .rpm file..."
fpm -s dir -t rpm --name mcsema --version ${VERSION} --maintainer "<mcsema@trailofbits.com>" --url "https://github.com/trailofbits/mcsema" --vendor "Trail of Bits" --prefix "/usr/local" -C ./package .
