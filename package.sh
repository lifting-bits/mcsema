#!/bin/bash

# gem install fpm
# sudo apt-get install rpm ruby-dev

echo "This script packages mcsema into deb and rpm packages"

echo "Cleaning old directory"
rm -rf ./package

# get a version number
GIT_HASH=$(git rev-parse --short HEAD)
VERSION=0.2-${GIT_HASH}
echo "MCSEMA Version is: ${VERSION}"

# collect the mcsema bins
mkdir package
MC_BINS=$(find ./build/mc-sema -executable -type f)
if [ "${MC_BINS}" == "" ]
then
    echo "Could not find mcsema binaries. Did you build mcsema?"
    exit -1
fi
for BINFILE in ${MC_BINS}
do
    echo "Packaging ${BINFILE}..."
    cp ${BINFILE} ./package/
done

echo "Building .deb file..."
fpm -s dir -t deb --name mcsema --version ${VERSION} --maintainer "<mcsema@trailofbits.com>" --url "https://github.com/trailofbits/mcsema" --vendor "Trail of Bits" --prefix "/usr/local/bin" -C ./package .

echo "Building .rpm file..."
fpm -s dir -t rpm --name mcsema --version ${VERSION} --maintainer "<mcsema@trailofbits.com>" --url "https://github.com/trailofbits/mcsema" --vendor "Trail of Bits" --prefix "/usr/local/bin" -C ./package .
