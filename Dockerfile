ARG LLVM_VERSION=900
ARG ARCH=amd64
ARG UBUNTU_VERSION=18.04
ARG DISTRO_BASE=ubuntu${UBUNTU_VERSION}
ARG BUILD_BASE=ubuntu:${UBUNTU_VERSION}
ARG LIBRARIES=/opt/trailofbits/libraries


# Run-time dependencies go here
FROM ${BUILD_BASE} as base
ARG UBUNTU_VERSION
ARG LIBRARIES
RUN apt-get update && \
    apt-get install -qqy --no-install-recommends zlib1g && \
    if [ "${UBUNTU_VERSION}" = "18.04" ] ; then \
      apt-get install -qqy --no-install-recommends libtinfo5 ; \
    else \
      apt-get install -qqy --no-install-recommends libtinfo6 ; \
    fi && \
    rm -rf /var/lib/apt/lists/*


# Will copy anvill installation from here
FROM trailofbits/anvill:llvm${LLVM_VERSION}-${DISTRO_BASE}-${ARCH} as anvill


# Build-time dependencies go here
FROM trailofbits/cxx-common:llvm${LLVM_VERSION}-${DISTRO_BASE}-${ARCH} as deps
ARG LIBRARIES
RUN apt-get update && \
    apt-get install -qqy python2.7 python3 python3-pip libc6-dev wget liblzma-dev zlib1g-dev libtinfo-dev curl git build-essential ninja-build libselinux1-dev libbsd-dev ccache && \
    if [ "$(uname -m)" = "x86_64" ]; then dpkg --add-architecture i386 && apt-get update && apt-get install -qqy gcc-multilib g++-multilib zip zlib1g-dev:i386; fi && \
    rm -rf /var/lib/apt/lists/* && \
    pip3 install ccsyspath

# needed for 20.04 support until we migrate to py3
RUN curl https://bootstrap.pypa.io/get-pip.py --output get-pip.py && python2.7 get-pip.py
RUN update-alternatives --install /usr/bin/python2 python2 /usr/bin/python2.7 1

COPY --from=anvill /opt/trailofbits/remill /opt/trailofbits/remill

ENV PATH="${LIBRARIES}/llvm/bin:${LIBRARIES}/cmake/bin:${LIBRARIES}/protobuf/bin:${PATH}" \
    CC="${LIBRARIES}/llvm/bin/clang" \
    CXX="${LIBRARIES}/llvm/bin/clang++" \
    TRAILOFBITS_LIBRARIES="${LIBRARIES}"

WORKDIR /mcsema

# Source code build
FROM deps as build
# Using this file:
# 1. wget https://raw.githubusercontent.com/trailofbits/mcsema/master/tools/Dockerfile
# 2. docker build -t=mcsema .
# 3. docker run --rm -it --ipc=host -v "${PWD}":/home/user/local mcsema

# If using IDA for CFG recovery, uncomment the following line:
# RUN sudo dpkg --add-architecture i386 && sudo apt-get install zip zlib1g-dev:i386 -y

COPY . ./

RUN mkdir -p ./build && cd ./build && \
    cmake -G Ninja -DCMAKE_PREFIX_PATH="/opt/trailofbits/remill" -DMCSEMA_DISABLED_ABI_LIBRARIES:STRING="" -DCMAKE_VERBOSE_MAKEFILE=True -DCMAKE_INSTALL_PREFIX=/opt/trailofbits/mcsema .. && \
    cmake --build . --target install

WORKDIR tests/test_suite_generator
RUN mkdir -p build && \
    cd build && \
    cmake -DMCSEMALIFT_PATH=/opt/trailofbits/mcsema/bin \
          -DMCSEMA_PREBUILT_CFG_PATH="$(pwd)/../generated/prebuilt_cfg/" \
	  -DMCSEMADISASS_PATH=/opt/trailofbits/mcsema/bin \
	  .. && \
    cmake --build . --target install

RUN cd test_suite && \
    PATH="/opt/trailofbits/mcsema/bin:${PATH}" python2.7 start.py



################################
# Left to reader to install    #
#  their disassembler (IDA/BN) #
################################
# But, as an example:
# ADD local-relative/path/to/binaryninja/ /root/binaryninja/
# ADD local-relative/path/to/.binaryninja/ /root/.binaryninja/ # <- Make sure there's no `lastrun` file
# RUN /root/binaryninja/scripts/linux-setup.sh


FROM base as dist
ARG LLVM_VERSION

# Allow for mounting of local folder
RUN mkdir -p /mcsema/local

COPY --from=build /opt/trailofbits/remill /opt/trailofbits/remill
COPY --from=build /opt/trailofbits/mcsema /opt/trailofbits/mcsema
COPY scripts/docker-lifter-entrypoint.sh /opt/trailofbits/mcsema
ENV LLVM_VERSION=llvm${LLVM_VERSION} \
    PATH="/opt/trailofbits/mcsema/bin:${PATH}"
ENTRYPOINT ["/opt/trailofbits/mcsema/docker-lifter-entrypoint.sh"]
