# Using this file:
# 1. wget https://raw.githubusercontent.com/trailofbits/mcsema/master/tools/Dockerfile
# 2. docker build -t=mcsema .
# 3. docker run --rm -it --ipc=host -v "${PWD}":/home/user/local mcsema

FROM ubuntu:18.04

RUN apt-get update && apt-get upgrade -y
RUN apt-get install git curl cmake python2.7 python-pip python-virtualenv wget build-essential gcc-multilib g++-multilib libtinfo-dev lsb-release zlib1g-dev -y

# If using IDA for CFG recovery, uncomment the following line:
# RUN sudo dpkg --add-architecture i386 && sudo apt-get install zip zlib1g-dev:i386 -y

# Set up enviornment in `/home/ToB`
WORKDIR /home/ToB

# Download everything and set up folder structure
RUN git clone --depth 1 https://github.com/trailofbits/mcsema.git && \ 
    export REMILL_VERSION=`cat ./mcsema/.remill_commit_id` && \
    git clone https://github.com/trailofbits/remill.git && \
    cd remill && \
    git checkout -b temp ${REMILL_VERSION} && \
    mv ../mcsema tools

RUN cd remill && ./scripts/build.sh

RUN cd remill/remill-build && make install

WORKDIR /home/user
################################
# Left to reader to install    #
#  their disassembler (IDA/BN) #
################################
# But, as an example:
# ADD local-relative/path/to/binaryninja/ /root/binaryninja/
# ADD local-relative/path/to/.binaryninja/ /root/.binaryninja/ # <- Make sure there's no `lastrun` file
# RUN /root/binaryninja/scripts/linux-setup.sh


# Allow for mounting of local folder
RUN mkdir local

CMD /bin/bash
