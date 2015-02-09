#!/bin/bash


if [ $# -eq 0 ]
then
    echo "No arguments supplied. Defaulting to DCMAKE_BUILD_TYPE=Release"
    BUILD_TYPE=Release
else
    BUILD_TYPE=$1
fi

echo "[x] Installing dependencies via apt-get"
sudo apt-get install -y gcc-multilib build-essential cmake nasm g++-multilib

if [ `getconf LONG_BIT` = "64" ]
then
    sudo apt-get install -y libc6-i386 libstdc++6:i386 lib32stdc++6
fi
echo "[x] Creating build directory"

mkdir build
cd build
echo "[x] Creating Makefiles"

cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=$BUILD_TYPE ..

make 
