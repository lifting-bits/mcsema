ARG LLVM_VERSION=800
ARG ARCH=amd64
ARG LIBRARIES=/opt/trailofbits/libraries
ARG DISTRO_BASE=ubuntu18.04

#FROM trailofbits/remill/llvm${LLVM_VERSION}-${DISTRO_BASE}-${arch}:latest as base
FROM trailofbits/remill:llvm${LLVM_VERSION}-${DISTRO_BASE}-${ARCH} as base
ARG LIBRARIES

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -qqy python2.7 wget zlib1g-dev && \
    if [ "$(uname -m)" = "x86_64" ]; then dpkg --add-architecture i386 && apt-get update && apt-get install -qqy zip zlib1g-dev:i386; fi && \
    rm -rf /var/lib/apt/lists/*

# needed for 20.04 support until we migrate to py3
RUN curl https://bootstrap.pypa.io/get-pip.py --output get-pip.py && python2.7 get-pip.py

# Using this file:
# 1. wget https://raw.githubusercontent.com/trailofbits/mcsema/master/tools/Dockerfile
# 2. docker build -t=mcsema .
# 3. docker run --rm -it --ipc=host -v "${PWD}":/home/user/local mcsema

# If using IDA for CFG recovery, uncomment the following line:
# RUN sudo dpkg --add-architecture i386 && sudo apt-get install zip zlib1g-dev:i386 -y

# Build in the remill build directory
RUN mkdir -p /remill/tools/mcsema
WORKDIR /remill/tools/mcsema

COPY . ./

#TODO(artem): find a way to use remill commit id; for now just use latest build of remill
# RUN cd /remill && git checkout -b temp $(</remill/tools/mcsema/.remil_commit_id) && cd /remill/tools/mcsema

ENV PATH="${LIBRARIES}/llvm/bin:${LIBRARIES}/cmake/bin:${LIBRARIES}/protobuf/bin:${PATH}"
ENV CC="${LIBRARIES}/llvm/bin/clang"
ENV CXX="${LIBRARIES}/llvm/bin/clang++"
ENV TRAILOFBITS_LIBRARIES="${LIBRARIES}"

RUN cd /remill/build && cmake .. && cmake --build . --target install

#WORKDIR /home/user
################################
# Left to reader to install    #
#  their disassembler (IDA/BN) #
################################
# But, as an example:
# ADD local-relative/path/to/binaryninja/ /root/binaryninja/
# ADD local-relative/path/to/.binaryninja/ /root/.binaryninja/ # <- Make sure there's no `lastrun` file
# RUN /root/binaryninja/scripts/linux-setup.sh


# Allow for mounting of local folder
RUN mkdir -p /mcsema/local
# CMD /bin/bash
