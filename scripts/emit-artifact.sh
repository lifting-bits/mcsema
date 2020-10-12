#!/bin/bash

# This script is run inside Github Actions CI to create an archive of a fully-built project

# install pixz for parallel xz
apt-get update
apt-get install -yqq pixz
# compress /opt/trailofbits/{mcsema,remill} and emit it to $1
echo "Compressing to: ${1}"
tar -Ipixz -cf "${1}" -C /opt/trailofbits mcsema remill