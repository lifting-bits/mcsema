#!/bin/bash

echo "This script packages mcsema into a .deb package"
echo "Cleaning old diretories"
rm -rf ./deb-build

GIT_DATE=$(git log -n 1 --format="%ai")
DATE=$(date --utc --date="${GIT_DATE}" +%Y%m%d%H%M)
VERSION=0.1-${DATE}


echo "MCSEMA Version is: ${VERSION}"

mkdir -p ./deb-build/mcsema_${VERSION}/opt/mcsema/bin/

cp -R ./debian ./deb-build/mcsema_${VERSION}/DEBIAN
echo "Version: ${VERSION}" | cat - ./debian/control > ./deb-build/mcsema_${VERSION}/DEBIAN/control

MC_BINS=$(find ./build/mc-sema -executable -type f)

if [ "${MC_BINS}" == "" ]
then
    echo "Could not find mcsema binaries. Did you build mcsema?"
    exit -1
fi

for BINFILE in ${MC_BINS}
do
    echo "Packaging ${BINFILE}..."
    cp ${BINFILE} ./deb-build/mcsema_${VERSION}/opt/mcsema/bin/
done


LLVM_BINS=$(find ./build/llvm-3.2 -executable -type f ! -name '*.so')
if [ "${LLVM_BINS}" == "" ]
then
    echo "Could not find LLVM binaries. Did you build mcsema?"
    exit -1
fi

for BINFILE in ${LLVM_BINS}
do
    echo "Packaging ${BINFILE}..."
    cp ${BINFILE} ./deb-build/mcsema_${VERSION}/opt/mcsema/bin/
done

echo "Building .deb file..."
dpkg-deb -v --build ./deb-build/mcsema_${VERSION}

