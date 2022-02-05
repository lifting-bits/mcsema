ARG LLVM_VERSION=11
ARG ARCH=amd64
ARG UBUNTU_VERSION=20.04
ARG DISTRO_BASE=ubuntu${UBUNTU_VERSION}
ARG BUILD_BASE=ubuntu:${UBUNTU_VERSION}
ARG LIBRARIES=/opt/trailofbits

# Using this file:
# 1. Clone the mcsema repo https://github.com/lifting-bits/mcsema
# 2. docker build -t=mcsema .
# To run the lifter
# 3. docker run --rm -it --ipc=host -v "${PWD}":/home/user/local mcsema
# To run the disassembler
# 4. docker run --rm --entrypoint=mcsema-disass -it --ipc=host -v "${PWD}":/home/user/local mcsema

# Run-time dependencies go here
FROM ${BUILD_BASE} as base
ARG UBUNTU_VERSION
ARG LIBRARIES
RUN apt-get update && \
    apt-get install -qqy --no-install-recommends python3 python3-pip python3-setuptools python3-six python3.8 zlib1g curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*


# Build-time dependencies go here
FROM trailofbits/cxx-common-vcpkg-builder-ubuntu:${UBUNTU_VERSION} as deps
ARG UBUNTU_VERSION
ARG ARCH
ARG LLVM_VERSION
ARG LIBRARIES
RUN apt-get update && \
    apt-get install -qqy python3 python3-pip libc6-dev wget liblzma-dev zlib1g-dev curl git build-essential ninja-build libselinux1-dev libbsd-dev ccache pixz xz-utils make rpm && \
    if [ "$(uname -m)" = "x86_64" ]; then dpkg --add-architecture i386 && apt-get update && apt-get install -qqy gcc-multilib g++-multilib zip zlib1g-dev:i386; fi && \
    rm -rf /var/lib/apt/lists/* && \
    pip3 install ccsyspath

# Build dependencies
RUN git clone --branch master https://github.com/lifting-bits/remill.git && \
    cd remill && git checkout -b release_710013a 710013a && \
    ./scripts/build.sh --llvm-version ${LLVM_VERSION} --prefix ${LIBRARIES} --download-dir /tmp

# Make this a separate RUN because the build script above downloads a lot
RUN cd remill && \
    cmake --build remill-build --target install -- -j "$(nproc)" && \
    cd ../ && \
    git clone --branch master https://github.com/lifting-bits/anvill.git && \
    ( cd anvill && git checkout -b release_bc3183b bc3183b ) && \
    mkdir -p anvill/build && cd anvill/build && \
    cmake -DCMAKE_VERBOSE_MAKEFILE=ON -DCMAKE_INSTALL_PREFIX=${LIBRARIES} -Dremill_DIR=${LIBRARIES}/lib/cmake/remill -DVCPKG_ROOT=/tmp/vcpkg_ubuntu-${UBUNTU_VERSION}_llvm-${LLVM_VERSION}_${ARCH} .. && \
    cmake --build . --target install -- -j "$(nproc)"

WORKDIR /mcsema

# Source code build
FROM deps as build
ARG UBUNTU_VERSION
ARG ARCH
ARG LLVM_VERSION
ARG LIBRARIES

COPY . ./

# Need to move python version-specific installation directory to general
# version directory since we don't know exactly which Python3 version Ubutnu
# ships with to set the environment variable PYTHONPATH in dist image
RUN mkdir -p ./build && cd ./build && \
    cmake -G Ninja -Danvill_DIR=${LIBRARIES}/lib/cmake/anvill -Dremill_DIR=${LIBRARIES}/lib/cmake/remill -DMCSEMA_DISABLED_ABI_LIBRARIES:STRING="" -DCMAKE_VERBOSE_MAKEFILE=True -DVCPKG_ROOT=/tmp/vcpkg_ubuntu-${UBUNTU_VERSION}_llvm-${LLVM_VERSION}_${ARCH} -DCMAKE_INSTALL_PREFIX=${LIBRARIES} .. && \
    cmake --build . --target install
RUN mv ${LIBRARIES}/lib/python3.* ${LIBRARIES}/lib/python3

# WORKDIR tests/test_suite_generator
# RUN mkdir -p build && \
#     cd build && \
#     cmake -DMCSEMALIFT_PATH=/opt/trailofbits/bin \
#           -DMCSEMA_PREBUILT_CFG_PATH="$(pwd)/../generated/prebuilt_cfg/" \
#       -DMCSEMADISASS_PATH=/opt/trailofbits/bin \
#       .. && \
#     cmake --build . --target install
#
# RUN cd test_suite && \
#     PATH="/opt/trailofbits/bin:${PATH}" python3 start.py

FROM base as dist
ARG LIBRARIES
ARG LLVM_VERSION

# Allow for mounting of local folder
RUN mkdir -p /mcsema/local

COPY --from=build ${LIBRARIES} ${LIBRARIES}
COPY scripts/docker-lifter-entrypoint.sh ${LIBRARIES}
ENV LLVM_VERSION=llvm${LLVM_VERSION} \
    PATH="${LIBRARIES}/bin:${PATH}" \
    PYTHONPATH="${LIBRARIES}/lib/python3/site-packages"
ENTRYPOINT ["/opt/trailofbits/docker-lifter-entrypoint.sh"]

################################
# Left to reader to install    #
#  their disassembler (IDA/BN) #
################################
# But, as an example:
# ADD local-relative/path/to/binaryninja/ /root/binaryninja/
# ADD local-relative/path/to/.binaryninja/ /root/.binaryninja/ # <- Make sure there's no `lastrun` file
# RUN /root/binaryninja/scripts/linux-setup.sh
